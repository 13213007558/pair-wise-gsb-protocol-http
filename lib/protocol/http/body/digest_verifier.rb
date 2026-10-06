# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "wrapper"
require_relative "../header/content_digest"

module Protocol
	module HTTP
		module Body
			# Verifies a message-content stream as it is read.
			#
			# When the digest is delivered in a trailer, {#result} remains pending until the stream
			# reaches end-of-file and the caller rechecks the header collection.
			class DigestVerifier < Wrapper
				# Wrap a message body and verify Content-Digest after the body has been consumed.
				def self.wrap(message, header_class = Header::ContentDigest, algorithms: header_class::ALLOWED_ALGORITHMS, &block)
					if body = message&.body
						if requires_complete_representation?(header_class) && message.respond_to?(:partial?) && message.partial?
							raise Header::Digest::IncompleteRepresentationError, "Cannot verify a complete representation digest using a partial message body"
						end

						message.body = new(body, message.headers, header_class, algorithms: algorithms, &block)
					end
				end

				def self.requires_complete_representation?(header_class)
					header_class.const_defined?(:REQUIRES_COMPLETE_REPRESENTATION, false) && header_class::REQUIRES_COMPLETE_REPRESENTATION
				end

				def initialize(body, headers, header_class = Header::ContentDigest, algorithms: header_class::ALLOWED_ALGORITHMS, callback: nil, &block)
					super(body)

					@headers = headers
					@header_class = header_class
					@hashes = header_class.hashes_for(algorithms)
					@callback = block || callback
					@result = nil
					@complete = false
				end

				attr :header_class
				attr :result

				def pending?
					@result.nil?
				end

				def verified?
					@result&.verified?
				end

				def read
					if chunk = super
						chunk = chunk.b
						@hashes.each_value{|hash| hash.update(chunk)}
						return chunk
					end

					@complete = true

					return nil
				end

				# Compute the final result from headers and trailers now visible to the caller.
				def finish!
					return @result unless @result.nil?

					header = @headers[@header_class::HEADER_NAME]

					return if header.nil? || (header.respond_to?(:empty?) && header.empty?)

					size = @hashes.values.map(&:length).max || 0
					@result = @header_class.verify_hashes(header, @hashes, size)
					@callback&.call(@result)
					@callback = nil

					return @result
				end

				def close(error = nil)
					if error
						@result ||= failure(:stream_error)
						@callback = nil
					elsif @complete
						finish!
					else
						@result ||= failure(:stream_closed)
						@callback = nil
					end

					@callback = nil

					super
				end

				def failure(reason)
					@header_class.verification_result(false, entries: [], size: 0, reason: reason)
				end
			end
		end
	end
end
