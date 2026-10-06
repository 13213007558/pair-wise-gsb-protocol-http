# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/repr_digest"
require "protocol/http/body/buffered"
require "protocol/http/body/digest_verifier"
require "protocol/http/body/deflate"
require "protocol/http/response"

require "zlib"

describe Protocol::HTTP::Header::ReprDigest do
	let(:representation) {Protocol::HTTP::Body::Buffered.wrap("Hello World")}
	let(:compressed_body) {Protocol::HTTP::Body::Deflate.for(representation, Protocol::HTTP::Body::ZStream::GZIP, Zlib::NO_COMPRESSION)}
	let(:compressed) {compressed_body.join}
	let(:partial) {compressed.byteslice(0, 5)}

	let(:header) {subject.generate(compressed).first}

	it "verifies a complete representation stream" do
		result = subject.verify(header, compressed)

		expect(result).to be(:verified?)
		expect(result.scope).to be == :selected_representation
		expect(result.byte_range).to be == :complete_representation
		expect(result.size).to be == compressed.bytesize
	end

	it "does not pass using only a partial byte range" do
		result = subject.verify(header, partial)

		expect(result).not.to be(:verified?)
		expect(result.byte_range).to be == :complete_representation
		expect(result.reason).to be == :mismatch
	end

	it "refuses to infer a complete representation from a 206 body" do
		headers = Protocol::HTTP::Headers.new
		headers["repr-digest"] = header.to_s
		response = Protocol::HTTP::Response[206, headers, Protocol::HTTP::Body::Buffered.wrap(partial)]

		expect do
			subject.verify_message(response)
		end.to raise_exception(subject::IncompleteRepresentationError)
	end

	it "refuses to wrap a 206 body as if it were a complete representation" do
		headers = Protocol::HTTP::Headers.new
		headers["repr-digest"] = header.to_s
		response = Protocol::HTTP::Response[206, headers, Protocol::HTTP::Body::Buffered.wrap(partial)]

		expect do
			Protocol::HTTP::Body::DigestVerifier.wrap(response, subject)
		end.to raise_exception(subject::IncompleteRepresentationError)
	end

	it "verifies a 206 response when the caller supplies the complete representation" do
		headers = Protocol::HTTP::Headers.new
		headers["repr-digest"] = header.to_s
		response = Protocol::HTTP::Response[206, headers, Protocol::HTTP::Body::Buffered.wrap(partial)]

		result = subject.verify_message(response, representation: StringIO.new(compressed))

		expect(result).to be(:verified?)
		expect(result.byte_range).to be == :complete_representation
		expect(result.size).to be == compressed.bytesize
	end
end
