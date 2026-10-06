# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2025-2026, by Samuel Williams.

require_relative "digest_fields"

module Protocol
	module HTTP
		module Header
			# The legacy `digest` header (RFC 3230) provides a digest of the message body for integrity verification.
			#
			# This header is obsoleted by RFC 9530: use {ContentDigest} (content-digest) for the message content and {ReprDigest} (repr-digest) for the complete representation instead.
			#
			# ## Examples
			#
			# ```ruby
			# digest = Digest.new("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
			# digest << "md5=9bb58f26192e4ba00f01e2e7b136bbd8"
			# puts digest.to_s
			# # => "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=, md5=9bb58f26192e4ba00f01e2e7b136bbd8"
			# ```
			class Digest < DigestFields
				# The header key.
				def self.key
					"digest"
				end
			end
		end
	end
end
