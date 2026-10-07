# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/www_authenticate"

describe Protocol::HTTP::Header::WWWAuthenticate do
	let(:header) {subject.parse(value)}
	
	def parse_error(value)
		subject.parse(value)
	rescue subject::ParseError => error
		return error
	end
	
	with "a single challenge with parameters" do
		let(:value) {'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"'}
		
		it "parses the challenge" do
			expect(header.size).to be == 1
			
			challenge = header[0]
			
			expect(challenge.scheme).to be == "Digest"
			expect(challenge).not.to be(:token68?)
			expect(challenge.parameters).to be == [
				["realm", "testrealm@host.com"],
				# Commas inside quoted strings belong to the parameter value, not the challenge list:
				["qop", "auth,auth-int"],
				["nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093"],
			]
		end
		
		it "can look up parameters by name" do
			expect(header[0]["realm"]).to be == "testrealm@host.com"
			expect(header[0]["REALM"]).to be == "testrealm@host.com"
			expect(header[0]["unknown"]).to be == nil
		end
	end
	
	with "multiple challenges in a single field value" do
		# A proxy may receive several challenges combined into one `www-authenticate` field, mixing auth-param and token68 forms:
		let(:value) {'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="abc123", Bearer mF_9.B5f-4.1JqM, Custom dGVzdC10b2tlbg=='}
		
		it "parses each challenge in order" do
			expect(header.size).to be == 3
			
			expect(header[0].scheme).to be == "Digest"
			expect(header[0].parameters).to be == [
				["realm", "testrealm@host.com"],
				["qop", "auth,auth-int"],
				["nonce", "abc123"],
			]
			
			expect(header[1].scheme).to be == "Bearer"
			expect(header[1]).to be(:token68?)
			expect(header[1].token68).to be == "mF_9.B5f-4.1JqM"
			expect(header[1].parameters).to be == []
			
			expect(header[2].scheme).to be == "Custom"
			expect(header[2]).to be(:token68?)
			expect(header[2].token68).to be == "dGVzdC10b2tlbg=="
		end
		
		it "serializes back to an equivalent header value" do
			expect(header.to_s).to be == 'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce=abc123, Bearer mF_9.B5f-4.1JqM, Custom dGVzdC10b2tlbg=='
			
			# Round-tripping preserves the parsed representation:
			expect(subject.parse(header.to_s)).to be == header
		end
	end
	
	with "an unknown scheme" do
		let(:value) {'UnknownScheme key="value", other=data'}
		
		it "preserves the scheme and parameters without interpreting them" do
			expect(header.size).to be == 1
			expect(header[0].scheme).to be == "UnknownScheme"
			expect(header[0].parameters).to be == [["key", "value"], ["other", "data"]]
		end
	end
	
	with "duplicate parameters" do
		let(:value) {'Digest qop=auth, qop=auth-int'}
		
		it "preserves duplicates in order for the caller to decide" do
			expect(header[0].parameters).to be == [["qop", "auth"], ["qop", "auth-int"]]
			
			# The convenience lookup returns the first occurrence:
			expect(header[0]["qop"]).to be == "auth"
		end
	end
	
	with "a challenge without credentials" do
		let(:value) {"Basic, Bearer token"}
		
		it "parses both challenges" do
			expect(header.size).to be == 2
			expect(header[0].scheme).to be == "Basic"
			expect(header[0].parameters).to be == []
			expect(header[1].scheme).to be == "Bearer"
			expect(header[1].token68).to be == "token"
		end
	end
	
	with "a token68 value that looks like a parameter" do
		# Trailing `=` padding must not be confused with an auth-param:
		let(:value) {"Bearer abcdef=="}
		
		it "parses the credentials as token68" do
			expect(header[0]).to be(:token68?)
			expect(header[0].token68).to be == "abcdef=="
		end
	end
	
	with "a quoted-string containing an equals sign" do
		let(:value) {'Basic realm="a=b", charset="UTF-8"'}
		
		it "assigns the equals sign to the parameter value" do
			expect(header[0].parameters).to be == [["realm", "a=b"], ["charset", "UTF-8"]]
		end
	end
	
	with "a quoted-string containing an escaped quote" do
		let(:value) {'Basic realm="a \\"quoted\\" realm"'}
		
		it "unquotes the parameter value" do
			expect(header[0]["realm"]).to be == 'a "quoted" realm'
		end
	end
	
	with "extra whitespace and empty list elements" do
		let(:value) {"  Basic ,, Bearer   token  "}
		
		it "parses both challenges" do
			expect(header.size).to be == 2
			expect(header[0].scheme).to be == "Basic"
			expect(header[1].scheme).to be == "Bearer"
			expect(header[1].token68).to be == "token"
		end
	end
	
	with "syntax errors" do
		it "reports the precise offset of an invalid credential" do
			error = parse_error("Basic @@@")
			
			expect(error).not.to be == nil
			expect(error.offset).to be == 6
			expect(error.value).to be == "Basic @@@"
			expect(error.message).to be(:include?, "offset 6")
		end
		
		it "reports the precise offset of a missing comma between challenges" do
			error = parse_error("Bearer token Digest")
			
			expect(error).not.to be == nil
			expect(error.offset).to be == 13
		end
		
		it "reports the precise offset of an empty value" do
			error = parse_error("")
			
			expect(error).not.to be == nil
			expect(error.offset).to be == 0
		end
	end
	
	with ".coerce" do
		it "coerces a string into a parsed header" do
			header = subject.coerce("Bearer token")
			
			expect(header).to be_a(subject)
			expect(header[0].scheme).to be == "Bearer"
		end
		
		it "coerces an array of challenges" do
			challenge = subject::Challenge.new("Basic")
			header = subject.coerce([challenge])
			
			expect(header).to be == [challenge]
		end
	end
	
	with ".trailer?" do
		it "is not allowed in trailers" do
			expect(subject.trailer?).to be == false
		end
	end
end

describe Protocol::HTTP::Header::WWWAuthenticate::Challenge do
	it "serializes a challenge with parameters" do
		challenge = subject.new("Digest", [["realm", "testrealm@host.com"], ["nonce", "abc123"]])
		
		expect(challenge.to_s).to be == 'Digest realm="testrealm@host.com", nonce=abc123'
	end
	
	it "serializes a challenge with token68 credentials" do
		challenge = subject.new("Bearer", token68: "abc123==")
		
		expect(challenge.to_s).to be == "Bearer abc123=="
	end
	
	it "serializes a challenge without credentials" do
		expect(subject.new("Basic").to_s).to be == "Basic"
	end
	
	it "rejects both token68 and parameters" do
		expect do
			subject.new("Bearer", [["a", "b"]], token68: "abc")
		end.to raise_exception(ArgumentError)
	end
	
	it "compares challenges for equality" do
		expect(subject.new("Basic")).to be == subject.new("Basic")
		expect(subject.new("Basic")).not.to be == subject.new("Bearer")
		expect(subject.new("Digest", [["a", "b"]])).not.to be == subject.new("Digest", [["a", "c"]])
	end
end
