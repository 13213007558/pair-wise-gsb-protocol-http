# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "digest_fields"

module Protocol
	module HTTP
		module Header
			# The content-digest header (RFC 9530) provides a digest of the message content: the bytes conveyed in this specific message, after content codings are applied. For a partial response (e.g. 206 Partial Content), it covers only the conveyed byte range.
			#
			# ## Examples
			#
			# ~~~ ruby
			# digest = ContentDigest.generate(body)
			# puts digest.to_s
			# # => "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
			#
			# result = ContentDigest.verify(body, digest)
			# result.verified? # => true
			# result.byte_range # => 0...5
			# ~~~
			class ContentDigest < DigestFields
				# The header key.
				def self.key
					"content-digest"
				end
				
				# The scope of bytes covered by this digest field.
				# @returns [Symbol] :content, as this digest covers the message content.
				def self.scope
					:content
				end
			end
		end
	end
end
