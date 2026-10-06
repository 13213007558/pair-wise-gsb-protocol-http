# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "digest_fields"

module Protocol
	module HTTP
		module Header
			# The repr-digest header (RFC 9530) provides a digest of the complete representation data: the selected representation, after content codings are applied. Unlike content-digest, it covers the entire representation even when the message only conveys part of it (e.g. a 206 Partial Content response), so it cannot be verified against partial message content - the complete representation stream is required.
			#
			# ## Examples
			#
			# ~~~ ruby
			# digest = ReprDigest.generate(representation_stream)
			# puts digest.to_s
			# # => "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
			#
			# result = ReprDigest.verify(representation_stream, digest)
			# result.verified? # => true
			# ~~~
			class ReprDigest < DigestFields
				# The header key.
				def self.key
					"repr-digest"
				end
				
				# The scope of bytes covered by this digest field.
				# @returns [Symbol] :representation, as this digest covers the complete representation data.
				def self.scope
					:representation
				end
			end
		end
	end
end
