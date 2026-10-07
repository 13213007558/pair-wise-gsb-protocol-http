# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "error"
require_relative "headers"
require_relative "middleware"
require_relative "body/buffered"

require_relative "vcdiff"

module Protocol
	module HTTP
		# RFC 3229 delta encoding helpers.
		module Delta
			VCDIFF = "vcdiff".freeze
			A_IM = "a-im".freeze
			IM = "im".freeze
			DELTA_BASE = "delta-base".freeze
			ETAG = "etag".freeze
			VARY = "vary".freeze
			CONTENT_ENCODING = "content-encoding".freeze
			CONTENT_LENGTH = "content-length".freeze
			IF_NONE_MATCH = "if-none-match".freeze
			
			IM_USED = 226
			
			# Encode a full response as an RFC 3229 vcdiff response when possible.
			#
			# @parameter response [Response] the complete current representation.
			# @parameter base [String] the representation selected by the caller.
			# @parameter base_etag [String] the strong entity tag of the base.
			# @parameter current_etag [String] the strong entity tag of the current representation.
			# @returns [Response] the mutated 226 response.
			def self.encode(response, base, base_etag, current_etag = response.headers[ETAG])
				base = binary(base, "base")
				base_etag = strong_etag(base_etag, "base ETag")
				current_etag = strong_etag(current_etag, "current ETag")
				
				raise ArgumentError, "Expected a response" unless response.is_a?(Response)
				if encoding = response.headers[CONTENT_ENCODING]
					raise UnsupportedInstanceManipulationError, "Content-Encoding is not supported with vcdiff: #{encoding.to_a.inspect}"
				end
				
				target = response.read || String.new.b
				delta = VCDiff.encode(base, target)
				
				response.headers.add(VARY, A_IM)
				response.status = IM_USED
				response.headers[IM] = VCDIFF
				response.headers[DELTA_BASE] = base_etag
				response.headers[ETAG] = current_etag
				response.headers.delete(CONTENT_LENGTH)
				response.body = Body::Buffered.new([delta], delta.bytesize)
				
				response
			end
			
			# Restore a 226 vcdiff response to its complete representation.
			#
			# @parameter response [Response] a 226 response.
			# @parameter base [String] the representation selected by the caller.
			# @parameter expected [String] the expected complete representation.
			# @returns [Response] the mutated 200 response containing the complete representation.
			def self.decode(response, base, base_etag, expected:, current_etag: response.headers[ETAG])
				apply(response, base, base_etag, expected: expected, current_etag: current_etag)
			end
			
			# Restore a 226 vcdiff response to its complete representation.
			#
			# @parameter response [Response] a 226 response.
			# @parameter base [String] the representation selected by the caller.
			# @parameter base_etag [String] the expected strong entity tag from `Delta-Base`.
			# @parameter expected [String] the expected complete representation.
			# @returns [Response] the mutated 200 response containing the complete representation.
			def self.apply(response, base, base_etag, expected:, current_etag: response.headers[ETAG])
				base = binary(base, "base")
				expected_etag = strong_etag(base_etag, "base ETag")
				
				raise ArgumentError, "Expected a response" unless response.is_a?(Response)
				
				case response.status
				when 200
					return response
				when IM_USED
					# Continue below.
				else
					raise InvalidDeltaBaseError, "Cannot restore response with status #{response.status}"
				end
				
				im = response.headers[IM]
				unless im&.include?(VCDIFF)
					raise UnsupportedInstanceManipulationError, "Unsupported instance manipulation: #{im.inspect}"
				end
				
				if encoding = response.headers[CONTENT_ENCODING]
					raise UnsupportedInstanceManipulationError, "Secondary compression is not supported: #{encoding.to_a.inspect}"
				end
				
				delta_base = response.headers[DELTA_BASE]
				if delta_base.nil?
					raise InvalidDeltaBaseError, "Missing Delta-Base header"
				end
				unless delta_base == expected_etag
					raise InvalidDeltaBaseError, "Unexpected Delta-Base: #{delta_base.inspect}, expected #{expected_etag.inspect}"
				end
				
				expected = binary(expected, "expected representation")
				
				delta = response.read
				target = VCDiff.decode(base, delta.to_s)
				
				unless target == expected
					raise InvalidDeltaBaseError, "Restored representation does not match the expected representation"
				end
				
				if current_etag
					current_etag = strong_etag(current_etag, "current ETag")
					response_etag = response.headers[ETAG]
					unless response_etag == current_etag
						raise InvalidDeltaBaseError, "Restored representation ETag does not match #{current_etag.inspect}"
					end
				end
				
				response.status = 200
				response.headers.delete(IM)
				response.headers.delete(DELTA_BASE)
				response.headers.delete(CONTENT_LENGTH)
				response.body = Body::Buffered.new([target], target.bytesize)
				
				response
			end
			
			def self.strong_etag(value, name = "ETag")
				raise InvalidDeltaBaseError, "Missing #{name}" if value.nil?
				value = value.to_s
				unless value.start_with?("\"") && value.end_with?("\"") && value.bytesize >= 2
					raise InvalidDeltaBaseError, "#{name} must be a strong entity tag: #{value.inspect}"
				end
				value
			end
			
			def self.binary(value, name)
				raise ArgumentError, "#{name} must be a String" unless value.is_a?(String)
				value.b.dup
			end
			
			# A server-side middleware which applies RFC 3229 vcdiff to a complete response.
			class Encoding < Middleware
				# @parameter delegate [Object] the downstream app or middleware.
				# @parameter bases [Hash] maps strong entity tags to caller-supplied base representations.
				def initialize(delegate, bases = {})
					super(delegate)
					@bases = bases
				end
				
				# @returns [Response] the complete response or a 226 vcdiff response.
				def call(request)
					response = @delegate.call(request)
					
					return response unless request.method == Methods::GET
					return response unless response.status == 200
					return response unless request.headers[A_IM]&.acceptable?(VCDIFF)
					return response unless response.body
					return response if response.headers[CONTENT_ENCODING]
					current_etag = response.headers[ETAG]
					raise InvalidDeltaBaseError, "Delta encoding requires a strong ETag" unless current_etag.is_a?(String) && !current_etag.weak?
					
					base_etag = select_base_etag(request, current_etag)
					return response unless base_etag
					
					base = @bases[base_etag]
					if base.nil?
						raise InvalidDeltaBaseError, "Missing caller-supplied representation for #{base_etag.inspect}"
					end
					
					Delta.encode(response, base, base_etag, current_etag)
				end
				
				private
				
				def select_base_etag(request, current_etag)
					tags = request.headers[IF_NONE_MATCH]
					return nil unless tags
					
					tags.reverse_each do |tag|
						next if tag == "*"
						next unless tag.start_with?("\"") && tag.end_with?("\"")
						next if tag == current_etag
						return tag if @bases.key?(tag)
					end
					
					nil
				end
			end
		end
	end
end
