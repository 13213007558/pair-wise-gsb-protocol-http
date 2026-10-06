# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/content_digest"
require "protocol/http/body/buffered"
require "protocol/http/body/deflate"
require "protocol/http/response"

require "zlib"

describe Protocol::HTTP::Header::ContentDigest do
	let(:representation) {Protocol::HTTP::Body::Buffered.wrap("Hello World")}
	let(:compressed_body) {Protocol::HTTP::Body::Deflate.for(representation, Protocol::HTTP::Body::ZStream::GZIP, Zlib::NO_COMPRESSION)}
	let(:compressed) {compressed_body.join}
	let(:partial) {compressed.byteslice(0, 5)}

	let(:full_header) {subject.generate(compressed).first}
	let(:partial_header) {subject.generate(partial).first}

	it "uses RFC 9530 syntax" do
		expect(full_header.to_s).to be =~ /\Asha-256=:[A-Za-z0-9+\/]+=*:\z/
		expect(full_header.entries.first.value).to be =~ /\A[A-Za-z0-9+\/]+=*\z/
	end

	it "verifies the exact message content bytes" do
		result = subject.verify(full_header, compressed)

		expect(result).to be(:verified?)
		expect(result.scope).to be == :message_content
		expect(result.byte_range).to be == :message_content
		expect(result.size).to be == compressed.bytesize
	end

	it "reads protocol body streams without passing a read length" do
		header, size = subject.generate("Hello World")
		body = Protocol::HTTP::Body::Buffered.wrap("Hello World")

		result = subject.verify(header, body)

		expect(result).to be(:verified?)
		expect(result.size).to be == size
	end

	it "does not verify a different message content range" do
		result = subject.verify(full_header, partial)

		expect(result).not.to be(:verified?)
		expect(result.reason).to be == :mismatch
		expect(result.byte_range).to be == :message_content
	end

	it "can verify a sliced 206 message body" do
		headers = Protocol::HTTP::Headers.new
		headers["content-digest"] = partial_header.to_s
		response = Protocol::HTTP::Response[206, headers, Protocol::HTTP::Body::Buffered.wrap(partial)]

		result = subject.verify_message(response)

		expect(result).to be(:verified?)
		expect(result.size).to be == partial.bytesize
	end

	it "can choose among allowed algorithms" do
		header, size = subject.generate(compressed, algorithms: ["sha-512", "sha-256"])

		result = subject.verify(header, compressed, algorithms: ["sha-256", "sha-512"])

		expect(result).to be(:verified?)
		expect(result.algorithm).to be == "sha-256"
		expect(size).to be == compressed.bytesize
	end

	it "does not pass when an allowed digest entry mismatches" do
		header = subject.parse(full_header.to_s)
		header << subject::Entry.new("sha-512", ("\0" * 64).b).to_s

		result = subject.verify(header, compressed, algorithms: ["sha-256", "sha-512"])

		expect(result).not.to be(:verified?)
		expect(result.algorithm).to be == "sha-512"
		expect(result.reason).to be == :mismatch
	end

	it "does not pass when no advertised algorithm is allowed" do
		header, _ = subject.generate(compressed, algorithms: ["sha-256"])

		result = subject.verify(header, compressed, algorithms: ["sha-512"])

		expect(result).not.to be(:verified?)
		expect(result.reason).to be == :unsupported_algorithm
	end

	it "rejects malformed base64 values" do
		header = subject.parse("sha-256=:not base64:")

		result = subject.verify(header, compressed)

		expect(result).not.to be(:verified?)
		expect(result.reason).to be == :invalid_digest
	end

	it "raises when asked to generate an unsupported algorithm" do
		expect do
			subject.generate(compressed, algorithms: ["sha-1"])
		end.to raise_exception(subject::UnsupportedAlgorithm)
	end
end
