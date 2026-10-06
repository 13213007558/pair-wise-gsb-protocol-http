# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "split"
require_relative "../error"

require "base64"
require "digest/sha2"
require "digest/sha1"
require "digest/md5"

module Protocol
	module HTTP
		module Header
			# Base class for HTTP digest fields (RFC 9530), shared by the content-digest and repr-digest headers, as well as the legacy digest header (RFC 3230).
			#
			# Digest fields carry a cryptographic hash of a byte stream, allowing recipients to verify integrity. The {ContentDigest} header covers the message content (the bytes conveyed in a specific message, which may be partial), while the {ReprDigest} header covers the complete representation data (the selected representation, after content codings are applied).
			class DigestFields < Split
				ParseError = Class.new(InvalidHeaderError)
				
				# https://www.rfc-editor.org/rfc/rfc9530.html#section-2
				ENTRY = /\A(?<algorithm>[a-zA-Z0-9][a-zA-Z0-9\-]*)\s*=\s*(?<value>.*)\z/
				
				# Matches a content-range header with a complete byte range, e.g. "bytes 0-99/1234".
				CONTENT_RANGE = /\Abytes\s+(?<first>\d+)-(?<last>\d+)\/(?<size>\d+|\*)\z/i
				
				# A single digest entry in a digest field.
				Entry = Struct.new(:algorithm, :value) do
					# Create a new digest entry.
					#
					# @parameter algorithm [String] the digest algorithm (e.g., "sha-256").
					# @parameter value [String] the encoded digest value, e.g. an RFC 9530 byte sequence (":base64:").
					def initialize(algorithm, value)
						super(algorithm.downcase, value)
					end
					
					# Convert the entry to its string representation.
					#
					# @returns [String] the formatted digest string.
					def to_s
						"#{algorithm}=#{value}"
					end
				end
				
				# Digest algorithms supported by this implementation, mapped to factory blocks. This is a subset of the IANA "HTTP Digest Algorithm Values" registry. Note that md5 and sha-1 are supported for legacy compatibility, but are excluded from {DEFAULT_ALLOWED_ALGORITHMS} as they are considered insecure by RFC 9530.
				ALGORITHMS = {
					"sha-256" => ->{::Digest::SHA256.new},
					"sha-384" => ->{::Digest::SHA384.new},
					"sha-512" => ->{::Digest::SHA512.new},
					"sha-1" => ->{::Digest::SHA1.new},
					"md5" => ->{::Digest::MD5.new},
				}
				
				# The default allow-list of algorithms used when verifying digests. Algorithms outside this list are reported as :disallowed and never treated as verified.
				DEFAULT_ALLOWED_ALGORITHMS = ["sha-256", "sha-384", "sha-512"].freeze
				
				# The default algorithm used when generating digests.
				DEFAULT_ALGORITHM = "sha-256"
				
				# Parse the digest field value into a list of digest entries.
				#
				# @returns [Array(Entry)] the list of digest entries with their algorithms and values.
				def entries
					self.map do |value|
						if match = value.match(ENTRY)
							Entry.new(match[:algorithm], match[:value])
						else
							raise ParseError.new("Could not parse digest value: #{value.inspect}")
						end
					end
				end
				
				# Whether this header is acceptable in HTTP trailers.
				# @returns [Boolean] true, as digest fields contain integrity hashes that can only be calculated after the entire message content is available.
				def self.trailer?
					true
				end
				
				# The header key used to extract this digest field from message headers.
				#
				# @returns [String | Nil] the header key, or nil for the base class.
				def self.key
					nil
				end
				
				# The scope of bytes covered by this digest field: :content for the message content, or :representation for the complete representation data.
				#
				# @returns [Symbol]
				def self.scope
					:content
				end
				
				# Encode raw digest bytes as an RFC 9530 byte sequence.
				#
				# @parameter digest [String] the raw binary digest.
				# @returns [String] the encoded value, e.g. ":X48E9qOk...=:".
				def self.encode_value(digest)
					":#{::Base64.strict_encode64(digest)}:"
				end
				
				# Decode a digest entry value into raw bytes. Supports RFC 9530 byte sequences (":base64:"), bare base64, and hexadecimal (legacy digest header).
				#
				# @parameter value [String] the encoded digest value.
				# @returns [String | Nil] the raw binary digest, or nil if the value could not be decoded.
				def self.decode_value(value)
					if value.start_with?(":") and value.end_with?(":") and value.bytesize > 1
						return strict_decode64(value[1...-1])
					end
					
					# Legacy hexadecimal encoding:
					if /\A(?:[0-9a-fA-F]{2})+\z/.match?(value)
						return [value].pack("H*")
					end
					
					# Legacy bare base64 encoding:
					return strict_decode64(value)
				end
				
				# Generate a digest field by consuming the given stream to completion. The caller explicitly chooses which byte stream is digested: the message content stream for content-digest, or the complete representation stream for repr-digest.
				#
				# @parameter stream [#read] the byte stream to digest, e.g. a {Body::Readable} or IO.
				# @parameter algorithms [Array(String)] the digest algorithms to generate; must all be supported.
				# @returns [DigestFields] the generated digest field.
				def self.generate(stream, algorithms: [DEFAULT_ALGORITHM])
					digests = algorithms.map do |algorithm|
						algorithm = algorithm.to_s.downcase
						
						unless factory = ALGORITHMS[algorithm]
							raise ArgumentError, "Unsupported digest algorithm: #{algorithm.inspect}"
						end
						
						[algorithm, factory.call]
					end
					
					consume(stream) do |chunk|
						digests.each{|_, digest| digest.update(chunk)}
					end
					
					header = self.new
					
					digests.each do |algorithm, digest|
						header << "#{algorithm}=#{encode_value(digest.digest)}"
					end
					
					return header
				end
				
				# Verify a stream against the given digest field, consuming the stream to completion. The caller explicitly provides the byte stream to check: the message content stream for content-digest, or the complete representation stream for repr-digest.
				#
				# @parameter stream [#read] the byte stream to verify.
				# @parameter header [DigestFields | String] the digest field to verify against.
				# @parameter algorithms [Array(String)] the allow-list of acceptable digest algorithms.
				# @parameter byte_range [Range | Nil] the byte range the stream represents, if known; reported in the result.
				# @returns [Verification] the verification result, including the verified byte range.
				def self.verify(stream, header, algorithms: DEFAULT_ALLOWED_ALGORITHMS, byte_range: nil)
					verifier = self.verifier(algorithms: algorithms)
					
					consume(stream) do |chunk|
						verifier.update(chunk)
					end
					
					return verifier.finish(header, byte_range: byte_range)
				end
				
				# Verify the body of a message against the digest field carried in its headers (including trailers). If the message is partial (e.g. a 206 Partial Content response), a repr-digest cannot be verified against the partial content and the result is :unverifiable; a content-digest is verified against the conveyed byte range.
				#
				# @parameter message [Request | Response] the message to verify; the body is consumed.
				# @parameter algorithms [Array(String)] the allow-list of acceptable digest algorithms.
				# @returns [Verification] the verification result, including the verified byte range.
				def self.verify_message(message, algorithms: DEFAULT_ALLOWED_ALGORITHMS)
					verifier = self.verifier(message, algorithms: algorithms)
					
					if body = message.body
						consume(body){|chunk| verifier.update(chunk)}
					end
					
					return verifier.finish
				end
				
				# Create a streaming verifier, for use when the digest field is conveyed as a trailer. Update it as chunks are read, and call {Verifier#finish} once the stream is complete to get the final result.
				#
				# @parameter message [Request | Response | Nil] the message being verified, used to extract the digest field and byte range when finishing.
				# @parameter algorithms [Array(String)] the allow-list of acceptable digest algorithms.
				# @returns [Verifier]
				def self.verifier(message = nil, algorithms: DEFAULT_ALLOWED_ALGORITHMS)
					Verifier.new(self, message, algorithms: algorithms)
				end
				
				# Determine whether a message conveys partial content, and the byte range of the representation it covers.
				#
				# @parameter message [Request | Response] the message to inspect.
				# @returns [Array(Boolean, Range | Nil)] whether the message is partial, and the conveyed byte range if known.
				def self.message_byte_range(message)
					if content_range = message.headers["content-range"]
						if match = CONTENT_RANGE.match(content_range.to_s)
							first = Integer(match[:first])
							last = Integer(match[:last])
							
							return true, (first...(last + 1))
						else
							return true, nil
						end
					end
					
					if message.respond_to?(:partial?) and message.partial?
						return true, nil
					end
					
					return false, nil
				end
				
				# Consume a byte stream, yielding each chunk. Supports bodies (#read with no arguments) and IO-like objects (#read with a length).
				def self.consume(stream)
					if stream.method(:read).arity == 0
						while chunk = stream.read
							yield chunk
						end
					else
						while chunk = stream.read(16 * 1024)
							yield chunk
						end
					end
				end
				
				# Compare two binary strings in constant time.
				def self.secure_compare(a, b)
					return false unless a.bytesize == b.bytesize
					
					different = 0
					
					a.bytes.zip(b.bytes) do |x, y|
						different |= x ^ y
					end
					
					return different == 0
				end
				
				# Check parsed digest entries against computed digests, according to the allow-list of algorithms.
				#
				# @parameter entries [Array(Entry)] the parsed digest entries.
				# @parameter digests [Hash] computed ::Digest instances, keyed by algorithm.
				# @parameter algorithms [Array(String)] the allow-list of acceptable digest algorithms.
				# @returns [Array(Verification::Outcome)] the outcome of each entry.
				def self.verify_entries(entries, digests, algorithms)
					entries.map do |entry|
						algorithm = entry.algorithm
						
						unless algorithms.include?(algorithm)
							next Verification::Outcome.new(entry, :disallowed)
						end
						
						unless digest = digests[algorithm]
							next Verification::Outcome.new(entry, :unsupported)
						end
						
						expected = decode_value(entry.value)
						computed = digest.digest
						
						if expected and secure_compare(expected, computed)
							Verification::Outcome.new(entry, :verified, computed)
						else
							Verification::Outcome.new(entry, :mismatch, computed)
						end
					end
				end
				
				# Strictly decode a base64 string, returning nil if it is invalid.
				def self.strict_decode64(value)
					::Base64.strict_decode64(value)
				rescue ArgumentError
					nil
				end
			end
		end
	end
end

require_relative "digest_fields/verification"
require_relative "digest_fields/verifier"
