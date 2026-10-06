# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/body/digest_verifier"
require "protocol/http/body/buffered"
require "protocol/http/header/content_digest"
require "protocol/http/headers"

describe Protocol::HTTP::Body::DigestVerifier do
	let(:content) {"Hello World"}
	let(:headers) {Protocol::HTTP::Headers.new}
	let(:source) {Protocol::HTTP::Body::Buffered.wrap(content)}
	let(:body) {subject.new(source, headers)}

	it "is pending before the stream reaches end-of-file" do
		expect(body.read).to be == "Hello World"
		expect(body).to be(:pending?)
		expect(body).not.to be(:verified?)
	end

	it "verifies a digest already present in the headers at end-of-file" do
		header, _ = Protocol::HTTP::Header::ContentDigest.generate(content)
		headers["content-digest"] = header.to_s

		result = nil
		body = subject.new(source, headers) {|verification| result = verification}

		expect(body.read).to be == "Hello World"
		expect(body).to be(:pending?)

		expect(body.read).to be == nil
		expect(body).to be(:pending?)

		body.finish!

		expect(result).to be(:verified?)
		expect(body.result).to be(:verified?)
		expect(body.result.byte_range).to be == :message_content
	end

	it "waits for a trailer until the stream has completed" do
		header, _ = Protocol::HTTP::Header::ContentDigest.generate(content)
		headers.trailer!
		body = subject.new(source, headers)

		expect(body.read).to be == "Hello World"
		expect(body.read).to be == nil

		headers.add("content-digest", header.to_s)
		result = body.finish!

		expect(result).to be(:verified?)
		expect(result.scope).to be == :message_content
	end

	it "gives a terminal failure when the stream is closed without a digest" do
		expect(body.read).to be == "Hello World"
		body.close

		expect(body).not.to be(:pending?)
		expect(body.result).not.to be(:verified?)
		expect(body.result.reason).to be == :stream_closed
	end

	it "can verify a header when consumed through each" do
		header, _ = Protocol::HTTP::Header::ContentDigest.generate(content)
		headers["content-digest"] = header.to_s
		body = subject.new(source, headers)

		expect(body.join).to be == content
		expect(body.result).to be(:verified?)
	end
end
