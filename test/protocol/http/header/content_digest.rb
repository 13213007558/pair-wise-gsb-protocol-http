# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/content_digest"
require "protocol/http/body/buffered"
require "protocol/http/response"
require "protocol/http/headers"
require "sus"

describe Protocol::HTTP::Header::ContentDigest do
	it "classifies parse errors as invalid headers" do
		expect(subject::ParseError.new).to be_a(Protocol::HTTP::InvalidHeaderError)
	end
	
	it "has a header key and content scope" do
		expect(subject.key).to be == "content-digest"
		expect(subject.scope).to be == :content
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
	
	with "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:" do
		let(:header) {subject.parse(description)}
		
		it "can parse multiple entries" do
			entries = header.entries
			expect(entries.size).to be == 2
			expect(entries[0].algorithm).to be == "sha-256"
			expect(entries[1].algorithm).to be == "sha-512"
		end
	end
	
	with "invalid-format-no-equals" do
		let(:header) {subject.parse(description)}
		
		it "raises ParseError for invalid format" do
			expect do
				header.entries
			end.to raise_exception(Protocol::HTTP::Header::ContentDigest::ParseError)
		end
	end
	
	with "headers policy" do
		it "is coerced by the headers policy" do
			headers = Protocol::HTTP::Headers.new
			headers["content-digest"] = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
			
			expect(headers["content-digest"]).to be_a(subject)
		end
	end
end
