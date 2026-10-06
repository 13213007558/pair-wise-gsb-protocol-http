# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/repr_digest"
require "protocol/http/body/buffered"
require "protocol/http/response"
require "protocol/http/headers"
require "sus"

describe Protocol::HTTP::Header::ReprDigest do
	it "classifies parse errors as invalid headers" do
		expect(subject::ParseError.new).to be_a(Protocol::HTTP::InvalidHeaderError)
	end
	
	it "has a header key and representation scope" do
		expect(subject.key).to be == "repr-digest"
		expect(subject.scope).to be == :representation
	end
	
	it "should be allowed as a trailer" do
		expect(subject.trailer?).to be == true
	end
	
	with "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:" do
		let(:header) {subject.parse(description)}
		
		it "can parse an RFC 9530 byte sequence entry" do
			entries = header.entries
			expect(entries.size).to be == 1
			expect(entries.first.algorithm).to be == "sha-256"
			expect(entries.first.value).to be == ":X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
		end
	end
	
	with "headers policy" do
		it "is coerced by the headers policy" do
			headers = Protocol::HTTP::Headers.new
			headers["repr-digest"] = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
			
			expect(headers["repr-digest"]).to be_a(subject)
		end
	end
	
	with "partial content" do
		let(:data) {"Hello World!"}
		
		it "cannot verify the complete representation digest against partial message content" do
			header = subject.generate(Protocol::HTTP::Body::Buffered.wrap(data))
			
			headers = Protocol::HTTP::Headers.new
			headers["content-range"] = "bytes 0-4/#{data.bytesize}"
			headers["repr-digest"] = header.to_s
			
			message = Protocol::HTTP::Response.new(nil, 206, headers, Protocol::HTTP::Body::Buffered.wrap("Hello"))
			
			result = subject.verify_message(message)
			expect(result.verified?).to be == false
			expect(result.status).to be == :unverifiable
			expect(result.scope).to be == :representation
		end
		
		it "verifies the complete representation stream explicitly provided by the caller" do
			header = subject.generate(Protocol::HTTP::Body::Buffered.wrap(data))
			
			result = subject.verify(Protocol::HTTP::Body::Buffered.wrap(data), header)
			expect(result.verified?).to be == true
			expect(result.byte_range).to be == (0...data.bytesize)
		end
	end
end
