# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2025-2026, by Samuel Williams.

require_relative "split"
require_relative "../quoted_string"
require_relative "../error"

require "digest"
require "stringio"

module Protocol
	module HTTP
		module Header
			# Parses the obsolete Digest header and provides the shared digest implementation.
			#
			# New messages should use ContentDigest or ReprDigest.
			class Digest < Split
				HEADER_NAME = "digest"
				SCOPE = :message_body
				BYTE_RANGE = :message_body

				ALLOWED_ALGORITHMS = ["sha-256", "sha-512"]
				DEFAULT_ALGORITHMS = ["sha-256"]

				READ_SIZE = 64 * 1024

				ParseError = Class.new(InvalidHeaderError)
				UnsupportedAlgorithm = Class.new(StandardError)
				MissingDigestError = Class.new(StandardError)
				IncompleteRepresentationError = Class.new(StandardError)

				# Legacy RFC 3230 syntax.
				ENTRY = /\A(?<algorithm>[a-zA-Z0-9][a-zA-Z0-9\-]*)\s*=\s*(?<value>.*)\z/

				# The outcome of reading an explicitly supplied byte stream.
				VerificationResult = Struct.new(:verified, :scope, :byte_range, :algorithm, :expected, :actual, :entries, :size, :reason, keyword_init: true) do
					alias verified? verified
				end

				Entry = Struct.new(:algorithm, :value) do
					def initialize(algorithm, value)
						if value.encoding == Encoding::BINARY
							value = self.class.encode_base64(value)
						end

						super(algorithm.downcase, value)
					end

					def digest
						encoded = value

						raise ParseError, "Invalid digest value: #{value.inspect}" if encoded.empty?

						if encoded.match?(/\A[0-9a-fA-F]+\z/) && encoded.bytesize.even?
							return [encoded].pack("H*")
						end

						self.class.decode_base64(encoded)
					rescue ArgumentError
						raise ParseError, "Invalid digest value: #{value.inspect}"
					end

					def to_s
						"#{algorithm}=#{value}"
					end

					def self.encode_base64(digest)
						[digest].pack("m0")
					end

					def self.decode_base64(value)
						pattern = /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}(?:==)?)\z/

						raise ArgumentError unless value.match?(pattern)

						value.unpack1("m0")
					end
				end

				def self.coerce(value)
					case value
					when self
						value
					when Digest
						self.new(value.to_a)
					when Array
						self.new(value.map(&:to_s))
					when nil
						self.new
					else
						self.parse(value.to_s)
					end
				end

				def entries
					map do |value|
						if match = value.match(self.class::ENTRY)
							self.class::Entry.new(match[:algorithm], match[:value])
						else
							raise ParseError.new("Could not parse digest value: #{value.inspect}")
						end
					end
				end

				# Read stream to completion and generate one entry for each selected algorithm.
				# The caller retains ownership of the stream and must ensure it contains the intended byte range.
				def self.generate(stream, algorithms: DEFAULT_ALGORITHMS)
					hashes = hashes_for(algorithms)
					size = update_hashes(hashes, stream)

					header = new
					hashes.each do |algorithm, hash|
						header << self::Entry.new(algorithm, hash.digest).to_s
					end

					return header, size
				end

				# Verify this header against the complete supplied stream.
				#
				# @returns [VerificationResult] a final result; unsupported or failed digests are never successful.
				def self.verify(header, stream, algorithms: ALLOWED_ALGORITHMS)
					hashes = hashes_for(algorithms)
					size = update_hashes(hashes, stream)

					verify_hashes(header, hashes, size)
				end

				# Verify hashes already computed from a complete stream.
				def self.verify_hashes(header, hashes, size = nil)
					header = coerce(header)
					entries = begin
						header.entries
					rescue ParseError
						return verification_result(false, size: size, reason: :invalid_digest)
					end

					raise MissingDigestError, "Missing #{self::HEADER_NAME} header" if entries.empty?

					supported_algorithms = hashes.keys.select do |algorithm|
						entries.any?{|entry| entry.algorithm == algorithm}
					end
					supported = supported_algorithms.flat_map do |algorithm|
						entries.select{|entry| entry.algorithm == algorithm}
					end

					if supported.empty?
						return verification_result(false, entries: entries, size: size, reason: :unsupported_algorithm)
					end

					supported.each do |entry|
						actual = hashes[entry.algorithm].digest

						expected = begin
							entry.digest
						rescue ParseError
							nil
						end

						if expected.nil?
							return verification_result(false, algorithm: entry.algorithm, expected: nil, actual: actual, entries: entries, size: size, reason: :invalid_digest)
						end

						if expected != actual
							return verification_result(false, algorithm: entry.algorithm, expected: expected, actual: actual, entries: entries, size: size, reason: :mismatch)
						end
					end

					algorithm = supported.first.algorithm
					actual = hashes[algorithm].digest

					verification_result(true, algorithm: algorithm, expected: actual, actual: actual, entries: entries, size: size)
				end

				# Verify a request or response. For 206 responses, Repr-Digest callers must supply the complete representation.
				def self.verify_message(message, representation: nil, algorithms: ALLOWED_ALGORITHMS)
					stream = representation

					if stream.nil?
						if const_defined?(:REQUIRES_COMPLETE_REPRESENTATION, false) && self::REQUIRES_COMPLETE_REPRESENTATION && message.respond_to?(:partial?) && message.partial?
							raise IncompleteRepresentationError, "Cannot verify a complete representation digest using a partial message body"
						end

						stream = message.body
					end

					verify(message.headers[self::HEADER_NAME], stream, algorithms: algorithms)
				end

				def self.hashes_for(algorithms)
					Array(algorithms).each_with_object({}) do |name, hashes|
						algorithm = name.to_s.downcase
						hashes[algorithm] = digest_for(algorithm).new
					end
				end

				def self.digest_for(algorithm)
					case algorithm
					in "sha-256"
						::Digest::SHA256
					in "sha-512"
						::Digest::SHA512
					in "md5"
						require "digest/md5"
						::Digest::MD5
					else
						raise UnsupportedAlgorithm, "Unsupported digest algorithm: #{algorithm.inspect}"
					end
				end

				def self.update_hashes(hashes, stream)
					size = 0

					each_chunk(stream) do |chunk|
						chunk = chunk.b
						size += chunk.bytesize
						hashes.each_value{|hash| hash.update(chunk)}
					end

					return size
				end

				def self.each_chunk(stream, &block)
					return enum_for(:each_chunk, stream) unless block
					return if stream.nil?

					if stream.is_a?(String)
						stream = StringIO.new(stream.b)
					end

					if (defined?(Body::Readable) && stream.is_a?(Body::Readable)) || stream.method(:read).arity == 0
						while chunk = stream.read
							yield chunk unless chunk.empty?
						end
					else
						while chunk = stream.read(READ_SIZE)
							break if chunk.empty?
							yield chunk
						end
					end
				end

				def self.verification_result(verified, algorithm: nil, expected: nil, actual: nil, entries: [], size: 0, reason: verified ? :match : nil)
					VerificationResult.new(
						verified: verified,
						scope: self::SCOPE,
						byte_range: self::BYTE_RANGE,
						algorithm: algorithm,
						expected: expected,
						actual: actual,
						entries: entries,
						size: size,
						reason: reason
					)
				end

				# Whether this header is acceptable in HTTP trailers.
				def self.trailer?
					true
				end
			end
		end
	end
end
