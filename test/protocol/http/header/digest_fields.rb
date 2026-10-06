# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/content_digest"
require "protocol/http/header/repr_digest"
require "protocol/http/header/digest"
require "protocol/http/body/buffered"
require "protocol/http/response"
require "protocol/http/headers"

require "stringio"
require "zlib"

describe Protocol::HTTP::Header::DigestFields do
	let(:data) {'{"hello": "world"}'}
	
	with ".encode_value and .decode_value" do
		it "round-trips RFC 9530 byte sequences" do
			digest = ::Digest::SHA256.digest(data)
			encoded = subject.encode_value(digest)
			
			expect(encoded).to be == ":X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
			expect(subject.decode_value(encoded)).to be == digest
		end
		
		it "decodes legacy bare base64 values" do
			expect(subject.decode_value("X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")).to be == ::Digest::SHA256.digest(data)
		end
		
		it "decodes legacy hexadecimal values" do
			expect(subject.decode_value("9bb58f26192e4ba00f01e2e7b136bbd8")).to be == ["9bb58f26192e4ba00f01e2e7b136bbd8"].pack("H*")
		end
		
		it "returns nil for undecodable values" do
			expect(subject.decode_value("not a digest!!!")).to be == nil
		end
	end
	
	with ".generate" do
		it "generates a digest field from a body stream" do
			header = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data))
			
			expect(header.to_s).to be == "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
		end
		
		it "generates a digest field from an IO stream" do
			header = Protocol::HTTP::Header::ContentDigest.generate(StringIO.new(data))
			
			expect(header.to_s).to be == "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
		end
		
		it "generates multiple algorithms" do
			header = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data), algorithms: ["sha-256", "sha-512"])
			
			expect(header.entries.map{|entry| entry.algorithm}).to be == ["sha-256", "sha-512"]
		end
		
		it "raises for unsupported algorithms" do
			expect do
				Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data), algorithms: ["crc32c"])
			end.to raise_exception(ArgumentError, message: be =~ /Unsupported digest algorithm/)
		end
	end
	
	with ".verify" do
		let(:header) {Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data))}
		
		it "verifies a matching stream and reports the verified byte range" do
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header)
			
			expect(result.verified?).to be == true
			expect(result.status).to be == :verified
			expect(result.scope).to be == :content
			expect(result.byte_range).to be == (0...data.bytesize)
			expect(result.algorithm).to be == "sha-256"
		end
		
		it "reports the explicitly provided byte range" do
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header, byte_range: 10...28)
			
			expect(result.byte_range).to be == (10...28)
		end
		
		it "does not verify a mismatched stream" do
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap("tampered"), header)
			
			expect(result.verified?).to be == false
			expect(result.status).to be == :mismatch
			expect(result.algorithm).to be == nil
		end
		
		it "accepts a raw header string" do
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header.to_s)
			
			expect(result.verified?).to be == true
		end
	end
	
	with "algorithm policy" do
		it "does not verify algorithms outside the default allow-list" do
			header = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data), algorithms: ["md5"])
			
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header)
			
			expect(result.verified?).to be == false
			expect(result.outcomes.first.status).to be == :disallowed
		end
		
		it "verifies legacy algorithms when explicitly allowed" do
			header = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data), algorithms: ["md5"])
			
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header, algorithms: ["md5"])
			
			expect(result.verified?).to be == true
			expect(result.algorithm).to be == "md5"
		end
		
		it "does not verify unknown algorithms" do
			header = Protocol::HTTP::Header::ContentDigest.parse("crc32c=:AAAAAA==:")
			
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header, algorithms: ["crc32c"])
			
			expect(result.verified?).to be == false
			expect(result.status).to be == :unsupported
			expect(result.outcomes.first.status).to be == :unsupported
		end
		
		it "selects an allowed algorithm from multiple entries" do
			header = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data), algorithms: ["md5", "sha-256"])
			
			result = Protocol::HTTP::Header::ContentDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header)
			
			expect(result.verified?).to be == true
			expect(result.algorithm).to be == "sha-256"
			expect(result.failures.size).to be == 1
			expect(result.failures.first.status).to be == :disallowed
		end
		
		it "verifies the legacy digest header with hexadecimal values" do
			header = Protocol::HTTP::Header::Digest.new("md5=#{::Digest::MD5.hexdigest(data)}")
			
			result = Protocol::HTTP::Header::Digest.verify(Protocol::HTTP::Body::Buffered.wrap(data), header, algorithms: ["md5"])
			
			expect(result.verified?).to be == true
		end
	end
	
	with "streaming verifier" do
		let(:body) {Protocol::HTTP::Body::Buffered.wrap(data)}
		
		it "is pending until the stream is finished" do
			verifier = Protocol::HTTP::Header::ContentDigest.verifier
			
			expect(verifier).to be(:pending?)
			expect(verifier.result.status).to be == :pending
			expect(verifier.result.verified?).to be == false
			
			verifier.update(data)
			expect(verifier.length).to be == data.bytesize
			expect(verifier).to be(:pending?)
			
			header = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data))
			result = verifier.finish(header)
			
			expect(verifier).not.to be(:pending?)
			expect(result.verified?).to be == true
			expect(verifier.result).to be_equal(result)
		end
		
		it "cannot be updated after finishing" do
			verifier = Protocol::HTTP::Header::ContentDigest.verifier
			verifier.finish(Protocol::HTTP::Header::ContentDigest.new)
			
			expect do
				verifier.update(data)
			end.to raise_exception(Protocol::HTTP::Error)
		end
		
		it "gives a final result only after the stream completes when the digest is a trailer" do
			headers = Protocol::HTTP::Headers.new
			headers.add("trailer", "content-digest")
			headers.trailer!
			
			message = Protocol::HTTP::Response.new(nil, 200, headers, body)
			verifier = Protocol::HTTP::Header::ContentDigest.verifier(message)
			
			# No final result is available while the stream is in progress:
			expect(verifier.result.status).to be == :pending
			expect(verifier.result.verified?).to be == false
			
			message.body.each{|chunk| verifier.update(chunk)}
			
			# The digest arrives as a trailer after the message content:
			headers.add("content-digest", Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data)).to_s)
			
			result = verifier.finish
			expect(result.verified?).to be == true
			expect(result.byte_range).to be == (0...data.bytesize)
		end
		
		it "is unverifiable when the digest field is missing" do
			message = Protocol::HTTP::Response.new(nil, 200, Protocol::HTTP::Headers.new, body)
			
			result = Protocol::HTTP::Header::ContentDigest.verify_message(message)
			
			expect(result.verified?).to be == false
			expect(result.status).to be == :unverifiable
		end
	end
	
	with "compressed and sliced representation" do
		let(:data) {"Hello World!" * 128}
		let(:compressed) do
			buffer = StringIO.new
			gzip = Zlib::GzipWriter.new(buffer)
			gzip.write(data)
			gzip.close
			buffer.string
		end
		
		it "distinguishes representation data from content codings" do
			# The repr-digest covers the representation data, i.e. the compressed bytes:
			repr_digest = Protocol::HTTP::Header::ReprDigest.generate(Protocol::HTTP::Body::Buffered.wrap(compressed))
			
			# It is not the digest of the uncompressed data:
			identity_digest = Protocol::HTTP::Header::ReprDigest.generate(Protocol::HTTP::Body::Buffered.wrap(data))
			expect(repr_digest.to_s).not.to be == identity_digest.to_s
			
			# Verifying the uncompressed data against the repr-digest fails:
			result = Protocol::HTTP::Header::ReprDigest.verify(Protocol::HTTP::Body::Buffered.wrap(data), repr_digest)
			expect(result.verified?).to be == false
			
			# For a complete 200 response, the message content is the representation data,
			# so content-digest and repr-digest cover the same bytes:
			content_digest = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(compressed))
			expect(content_digest.entries.first.value).to be == repr_digest.entries.first.value
			
			headers = Protocol::HTTP::Headers.new
			headers["content-encoding"] = "gzip"
			headers["repr-digest"] = repr_digest.to_s
			message = Protocol::HTTP::Response.new(nil, 200, headers, Protocol::HTTP::Body::Buffered.wrap(compressed))
			
			result = Protocol::HTTP::Header::ReprDigest.verify_message(message)
			expect(result.verified?).to be == true
			expect(result.scope).to be == :representation
			expect(result.byte_range).to be == (0...compressed.bytesize)
		end
		
		it "distinguishes partial content from the complete representation" do
			slice = compressed.byteslice(0...10)
			
			repr_digest = Protocol::HTTP::Header::ReprDigest.generate(Protocol::HTTP::Body::Buffered.wrap(compressed))
			content_digest = Protocol::HTTP::Header::ContentDigest.generate(Protocol::HTTP::Body::Buffered.wrap(slice))
			
			# The content-digest of the slice differs from the repr-digest of the complete representation:
			expect(content_digest.entries.first.value).not.to be == repr_digest.entries.first.value
			
			headers = Protocol::HTTP::Headers.new
			headers["content-encoding"] = "gzip"
			headers["content-range"] = "bytes 0-9/#{compressed.bytesize}"
			headers["content-digest"] = content_digest.to_s
			headers["repr-digest"] = repr_digest.to_s
			
			message = Protocol::HTTP::Response.new(nil, 206, headers, Protocol::HTTP::Body::Buffered.wrap(slice))
			
			# The content-digest verifies the conveyed byte range of the partial content:
			content_result = Protocol::HTTP::Header::ContentDigest.verify_message(message)
			expect(content_result.verified?).to be == true
			expect(content_result.scope).to be == :content
			expect(content_result.byte_range).to be == (0...10)
			
			# The repr-digest of the complete representation cannot be verified against partial content:
			repr_result = Protocol::HTTP::Header::ReprDigest.verify_message(message)
			expect(repr_result.verified?).to be == false
			expect(repr_result.status).to be == :unverifiable
			
			# It verifies against the complete representation stream:
			full_result = Protocol::HTTP::Header::ReprDigest.verify(Protocol::HTTP::Body::Buffered.wrap(compressed), headers["repr-digest"])
			expect(full_result.verified?).to be == true
			expect(full_result.scope).to be == :representation
			expect(full_result.byte_range).to be == (0...compressed.bytesize)
		end
	end
end
