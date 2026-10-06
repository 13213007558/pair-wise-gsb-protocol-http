# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Protocol
	module HTTP
		module Header
			class DigestFields < Split
				# A streaming digest verifier. Update it with chunks as they are read from the message content or representation stream, then call {#finish} once the stream is complete to compute the final {Verification}. This is especially useful when the digest field is conveyed as a trailer, which is only available after the stream completes.
				class Verifier
					def initialize(header_class, message = nil, algorithms: DigestFields::DEFAULT_ALLOWED_ALGORITHMS)
						@header_class = header_class
						@message = message
						@algorithms = algorithms.map{|algorithm| algorithm.to_s.downcase}.freeze
						
						@digests = {}
						
						@algorithms.each do |algorithm|
							if factory = ALGORITHMS[algorithm]
								@digests[algorithm] = factory.call
							end
						end
						
						@length = 0
						@verification = nil
					end
					
					# @attribute [Class] the digest field class being verified (e.g. {ContentDigest}).
					attr :header_class
					
					# @attribute [Request | Response | Nil] the message being verified, if any.
					attr :message
					
					# @attribute [Array(String)] the allow-list of acceptable digest algorithms.
					attr :algorithms
					
					# @attribute [Integer] the number of bytes consumed so far.
					attr :length
					
					# Update the computed digests with the next chunk of the stream.
					def update(chunk)
						if @verification
							raise Error, "The stream has already been finished!"
						end
						
						@digests.each_value{|digest| digest.update(chunk)}
						@length += chunk.bytesize
						
						return self
					end
					
					alias << update
					
					# Whether no bytes have been consumed yet.
					def empty?
						@length == 0
					end
					
					# Whether the stream has not been finished yet.
					def pending?
						@verification.nil?
					end
					
					# The current verification result. If the stream has not been finished, a pending result is returned - the final result is only available after {#finish}.
					def result
						@verification || Verification.pending(@header_class.scope)
					end
					
					# Finish the stream and compute the final verification result.
					#
					# @parameter header [DigestFields | String | Nil] the digest field to verify against; extracted from the message headers (including trailers) if not given.
					# @parameter byte_range [Range | Nil] the byte range the stream represents; derived from the message content-range header if not given.
					# @returns [Verification] the final verification result.
					def finish(header = nil, byte_range: nil)
						if @message
							header ||= @message.headers[@header_class.key]
							
							partial, message_range = @header_class.message_byte_range(@message)
							byte_range ||= message_range
							
							if partial and @header_class.scope == :representation
								return @verification = Verification.unverifiable(
									:representation,
									"Cannot verify #{@header_class.key} against partial message content: the complete representation stream is required."
								)
							end
						end
						
						unless header
							return @verification = Verification.unverifiable(
								@header_class.scope,
								"No #{@header_class.key} digest field present."
							)
						end
						
						unless header.is_a?(DigestFields)
							header = @header_class.coerce(header)
						end
						
						byte_range ||= (0...@length)
						
						outcomes = @header_class.verify_entries(header.entries, @digests, @algorithms)
						
						return @verification = Verification.new(
							@header_class.scope,
							byte_range: byte_range,
							outcomes: outcomes,
						)
					end
				end
			end
		end
	end
end
