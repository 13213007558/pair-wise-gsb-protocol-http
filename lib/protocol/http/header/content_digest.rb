# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "digest"

module Protocol
	module HTTP
		module Header
			# The Content-Digest header verifies the exact bytes in the current message content.
			#
			# For a 206 response, pass the partial body carried by the response.
			class ContentDigest < Digest
				HEADER_NAME = "content-digest"
				SCOPE = :message_content
				BYTE_RANGE = :message_content

				ENTRY = /\A(?<algorithm>[a-zA-Z0-9][a-zA-Z0-9\-]*)\s*=\s*:(?<value>[!-~]+):\s*\z/

				class Entry < Digest::Entry
					def self.encode(digest)
						":#{encode_base64(digest)}:"
					end

					def initialize(algorithm, value)
						if value.encoding == Encoding::BINARY
							value = self.class.encode(value)
						end

						super
					end

					def digest
						self.class.decode_base64(value.delete_prefix(":").delete_suffix(":"))
					rescue ArgumentError
						raise ParseError, "Invalid base64 digest value: #{value.inspect}"
					end

					def to_s
						"#{algorithm}=:#{value.delete_prefix(":").delete_suffix(":")}:"
					end
				end
			end
		end
	end
end
