# frozen_string_literal: true

require_relative "error"
require_relative "request"
require_relative "response"
require_relative "body/buffered"

module Protocol
	module HTTP
		# Helpers for delta-encoded responses (RFC 3229) using VCDIFF (RFC 3284).
		#
		# The base instance is always provided directly by the caller: fetching
		# and cache management are the responsibility of the caller.
		module Delta
			# Raised when a delta response cannot be produced or applied.
			class Error < Protocol::HTTP::Error
			end
			
			# The status code of delta-encoded responses: 226 IM Used.
			IM_USED = 226
			
			# The request header listing acceptable instance manipulations.
			A_IM = "a-im"
			
			# The response header listing the instance manipulations applied.
			IM = "im"
			
			# The response header identifying the base instance by entity tag.
			DELTA_BASE = "delta-base"
			
			# The instance manipulation token for VCDIFF deltas.
			VCDIFF = "vcdiff"
			
			# Whether the request indicates acceptance of VCDIFF deltas using the
			# A-IM header.
			#
			# @parameter request [Request] The incoming request.
			# @returns [Boolean]
			def self.accepts?(request)
				if header = request.headers[A_IM]
					Array(header).any? {|token| token.strip.downcase == VCDIFF}
				else
					false
				end
			end
			
			# Encode a full response as a delta against the provided base
			# instance, producing a 226 (IM Used) response.
			#
			# @parameter response [Response] The full (200) response to encode.
			# @parameter base [String] The body of the base instance.
			# @parameter etag [String] The entity tag of the base instance.
			# @returns [Response] The delta response, with IM and Delta-Base
			#   headers and a VCDIFF delta body.
			def self.encode_response(response, base, etag)
				unless response.ok?
					raise ArgumentError, "Cannot delta-encode response with status #{response.status}!"
				end
				
				if body = response.body
					target = body.join || ""
				else
					raise ArgumentError, "Cannot delta-encode response without a body!"
				end
				
				delta = VCDiff.encode(base, target)
				
				headers = response.headers.dup
				headers.delete("content-length")
				headers[IM] = VCDIFF
				headers[DELTA_BASE] = etag
				
				# The delta is only valid for requests which accept VCDIFF and hold
				# the base instance:
				headers.add("vary", A_IM)
				headers.add("vary", "if-none-match")
				
				return Response.new(response.version, IM_USED, headers, Body::Buffered.wrap([delta]), response.protocol)
			end
			
			# Apply a 226 (IM Used) delta response to the provided base instance,
			# reconstructing the full response.
			#
			# The relationship between the status, the IM header and the
			# Delta-Base header is validated, and the base must match the
			# Delta-Base entity tag: a mismatched base never produces a
			# seemingly valid 200 response.
			#
			# @parameter response [Response] The delta (226) response.
			# @parameter base [String] The body of the base instance.
			# @parameter etag [String] The entity tag of the base instance.
			# @returns [Response] The reconstructed full (200) response.
			# @raises [Error] If the response is not a valid VCDIFF delta response
			#   for the provided base.
			def self.decode_response(response, base, etag)
				unless response.status == IM_USED
					raise Error, "Cannot apply delta: expected status #{IM_USED} (IM Used), got #{response.status}!"
				end
				
				im = response.headers[IM]
				
				unless im and Array(im).any? {|token| token.strip.downcase == VCDIFF}
					raise Error, "Cannot apply delta: response does not include #{VCDIFF} in the #{IM} header!"
				end
				
				delta_base = response.headers[DELTA_BASE]
				
				if delta_base.nil?
					raise Error, "Cannot apply delta: missing #{DELTA_BASE} header!"
				end
				
				unless delta_base.to_s == etag.to_s
					raise Error, "Cannot apply delta: base #{etag} does not match #{DELTA_BASE} #{delta_base}!"
				end
				
				unless (body = response.body) and (delta = body.join)
					raise Error, "Cannot apply delta: response has no body!"
				end
				
				# Any failure here, e.g. caused by a mismatched base, raises an
				# error rather than producing a corrupt representation:
				instance = VCDiff.decode(base, delta)
				
				headers = response.headers.dup
				headers.delete(IM)
				headers.delete(DELTA_BASE)
				headers.delete("content-length")
				
				return Response.new(response.version, 200, headers, Body::Buffered.wrap([instance]), response.protocol)
			end
		end
	end
end

require_relative "delta/vcdiff"
