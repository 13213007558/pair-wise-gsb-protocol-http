# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "content_digest"

module Protocol
	module HTTP
		module Header
			# The Repr-Digest header verifies the complete selected representation.
			#
			# A 206 response body is only one byte range and must not be used unless the caller
			# explicitly reassembles or otherwise provides the complete representation stream.
			class ReprDigest < ContentDigest
				HEADER_NAME = "repr-digest"
				SCOPE = :selected_representation
				BYTE_RANGE = :complete_representation
				REQUIRES_COMPLETE_REPRESENTATION = true
			end
		end
	end
end
