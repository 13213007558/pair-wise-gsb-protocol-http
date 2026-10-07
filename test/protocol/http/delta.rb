#!/usr/bin/env ruby
# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/delta"

describe Protocol::HTTP::Delta do
	let(:base_etag) {'"base"'}
	let(:current_etag) {'"current"'}
	let(:base) {"Hello World"}
	let(:target) {"Hello World!"}
	
	def response(body = target)
		Protocol::HTTP::Response[200, Protocol::HTTP::Headers[
			"content-type" => "text/plain",
			"etag" => current_etag
		], [body]]
	end
	
	it "encodes and restores a vcdiff response with RFC 3229 headers" do
		encoded = subject.encode(response, base, base_etag, current_etag)
		delta = encoded.read
		
		expect(encoded.status).to be == 226
		expect(encoded.headers["im"]).to be == ["vcdiff"]
		expect(encoded.headers["delta-base"]).to be == base_etag
		expect(encoded.headers["etag"]).to be == current_etag
		expect(encoded.headers).to have_keys("vary")
		expect(encoded.headers).not.to have_keys("content-length")
		expect(delta).to be(:start_with?, Protocol::HTTP::VCDiff::MAGIC)
		
		encoded_response = Protocol::HTTP::Response[226, encoded.headers.dup, Protocol::HTTP::Body::Buffered.wrap(delta)]
		restored = subject.apply(encoded_response, base, base_etag, expected: target)
		
		expect(restored.status).to be == 200
		expect(restored.headers).not.to have_keys("im", "delta-base")
		expect(restored.headers["etag"]).to be == current_etag
		expect(restored.read).to be == target
	end
	
	it "does not restore a delta when the base tag does not match" do
		encoded = subject.encode(response, base, base_etag, current_etag)
		delta = encoded.read
		encoded_response = Protocol::HTTP::Response[226, encoded.headers.dup, Protocol::HTTP::Body::Buffered.wrap(delta)]
		
		expect do
			subject.apply(encoded_response, base, '"other"', expected: target)
		end.to raise_exception(Protocol::HTTP::InvalidDeltaBaseError)
		
		expect(encoded_response.status).to be == 226
	end
	
	it "does not let a wrong base produce a 200 response body" do
		encoded = subject.encode(response, base, base_etag, current_etag)
		delta = encoded.read
		encoded_response = Protocol::HTTP::Response[226, encoded.headers.dup, Protocol::HTTP::Body::Buffered.wrap(delta)]
		
		expect do
			subject.apply(encoded_response, "Goodbye Mars", base_etag, expected: target)
		end.to raise_exception(Protocol::HTTP::Error)
		
		expect(encoded_response.status).to be == 226
	end
	
	it "rejects non-vcdiff instance manipulations" do
		wrong = response
		wrong.status = 226
		wrong.headers["im"] = "gdiff"
		wrong.headers["delta-base"] = base_etag
		wrong.body = Protocol::HTTP::Body::Buffered.wrap("x")
		
		expect do
			subject.apply(wrong, base, base_etag, expected: target)
		end.to raise_exception(Protocol::HTTP::UnsupportedInstanceManipulationError)
	end
	
	with "middleware" do
		let(:bases) {{base_etag => base}}
		
		it "negotiates vcdiff using a caller-supplied base" do
			app = proc {response}
			middleware = subject::Encoding.new(app, bases)
			request = Protocol::HTTP::Request["GET", "/", Protocol::HTTP::Headers[
				"a-im" => "vcdiff",
				"if-none-match" => base_etag
			]]
			
			encoded = middleware.call(request)
			
			expect(encoded.status).to be == 226
			expect(encoded.headers["im"]).to be == ["vcdiff"]
			expect(encoded.headers["delta-base"]).to be == base_etag
		end
		
		it "leaves the complete response unchanged without a selected base" do
			app = proc {response}
			middleware = subject::Encoding.new(app, bases)
			request = Protocol::HTTP::Request["GET", "/", Protocol::HTTP::Headers["a-im" => "vcdiff"]]
			
			complete = middleware.call(request)
			
			expect(complete.status).to be == 200
			expect(complete.headers).not.to have_keys("im", "delta-base")
		end

		it "rejects weak entity tags" do
			complete = response
			complete.headers["etag"] = "W/\"current\""
			app = proc {complete}
			middleware = subject::Encoding.new(app, base_etag => base)
			request = Protocol::HTTP::Request["GET", "/", Protocol::HTTP::Headers[
				"a-im" => "vcdiff",
				"if-none-match" => base_etag
			]]
			
			expect do
				middleware.call(request)
			end.to raise_exception(Protocol::HTTP::InvalidDeltaBaseError)
		end

		it "does not download or schedule a missing caller-supplied base" do
			app = proc {response}
			middleware = subject::Encoding.new(app)
			request = Protocol::HTTP::Request["GET", "/", Protocol::HTTP::Headers[
				"a-im" => "vcdiff",
				"if-none-match" => base_etag
			]]
			
			complete = middleware.call(request)
			expect(complete.status).to be == 200
			expect(complete.read).to be == target
		end
	end
end
