
# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/www_authenticate"
require "protocol/http/headers"

describe Protocol::HTTP::Header::WWWAuthenticate::Challenge do
	it "can represent a challenge without credentials" do
		challenge = subject.new("Basic")
		
		expect(challenge.scheme).to be == "Basic"
		expect(challenge.token68).to be_nil
		expect(challenge.parameters).to be_nil
		expect(challenge).not.to be(:token68?)
		expect(challenge.to_s).to be == "Basic"
	end
	
	it "can represent a token68 challenge" do
		challenge = subject.new("Basic", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
		
		expect(challenge).to be(:token68?)
		expect(challenge.to_s).to be == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
	end
	
	it "can represent a challenge with parameters" do
		challenge = subject.new("Digest", nil, [["realm", "test"], ["qop", "auth,auth-int"]])
		
		expect(challenge["realm"]).to be == "test"
		expect(challenge["REALM"]).to be == "test"
		expect(challenge["nonce"]).to be_nil
		expect(challenge.to_s).to be == 'Digest realm=test, qop="auth,auth-int"'
	end
end

describe Protocol::HTTP::Header::WWWAuthenticate do
	it "classifies parse errors as invalid headers" do
		expect(subject::ParseError.new("Error", "", 0)).to be_a(Protocol::HTTP::InvalidHeaderError)
	end
	
	let(:header) {subject.parse(description)}
	
	with 'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", Bearer realm="api", error="invalid_token", CustomKey dGVzdC1rZXkudmFsdWU=' do
		it "parses multiple challenges on a single line, in order" do
			expect(header.size).to be == 3
			
			digest, bearer, custom = header.to_a
			
			expect(digest.scheme).to be == "Digest"
			expect(digest.parameters).to be == [
				["realm", "testrealm@host.com"],
				["qop", "auth,auth-int"],
				["nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093"],
			]
			
			expect(bearer.scheme).to be == "Bearer"
			expect(bearer.parameters).to be == [
				["realm", "api"],
				["error", "invalid_token"],
			]
			
			expect(custom.scheme).to be == "CustomKey"
			expect(custom).to be(:token68?)
			expect(custom.token68).to be == "dGVzdC1rZXkudmFsdWU="
		end
		
		it "round-trips through the encoder" do
			expect(subject.parse(header.to_s)).to be == header
		end
	end
	
	with "commas and equals signs" do
		it "does not split quoted-string values on commas" do
			header = subject.parse('Digest realm="a, b", nonce="x"')
			
			expect(header.size).to be == 1
			expect(header[0].parameters).to be == [["realm", "a, b"], ["nonce", "x"]]
		end
		
		it "treats a comma followed by an auth-param as a parameter separator" do
			header = subject.parse("Digest a=1, b=2")
			
			expect(header.size).to be == 1
			expect(header[0].parameters).to be == [["a", "1"], ["b", "2"]]
		end
		
		it "treats a comma followed by a scheme as a challenge separator" do
			header = subject.parse("Digest a=1, Bearer c=2")
			
			expect(header.size).to be == 2
			expect(header[0].scheme).to be == "Digest"
			expect(header[0].parameters).to be == [["a", "1"]]
			expect(header[1].scheme).to be == "Bearer"
			expect(header[1].parameters).to be == [["c", "2"]]
		end
		
		it "parses token68 credentials with trailing padding" do
			header = subject.parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
			
			expect(header[0]).to be(:token68?)
			expect(header[0].token68).to be == "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		end
		
		it "parses token68 credentials followed by another challenge" do
			header = subject.parse("Basic abc=, Digest a=b")
			
			expect(header.size).to be == 2
			expect(header[0].token68).to be == "abc="
			expect(header[1].scheme).to be == "Digest"
		end
	end
	
	with "unknown schemes and duplicate parameters" do
		it "preserves unknown schemes" do
			header = subject.parse("NewScheme token68value, Other x=1")
			
			expect(header.map(&:scheme)).to be == ["NewScheme", "Other"]
		end
		
		it "preserves duplicate parameters in order" do
			header = subject.parse("Digest a=1, a=2, b=3")
			
			expect(header[0].parameters).to be == [["a", "1"], ["a", "2"], ["b", "3"]]
			expect(header[0]["a"]).to be == "1"
		end
		
		it "preserves challenges without credentials" do
			header = subject.parse("Basic, Digest realm=x")
			
			expect(header.size).to be == 2
			expect(header[0].scheme).to be == "Basic"
			expect(header[0].token68).to be_nil
			expect(header[0].parameters).to be_nil
		end
	end
	
	with "syntax errors" do
		it "reports the offset of an unexpected character" do
			expect do
				subject.parse('Digest realm="x" garbage')
			end.to raise_exception(subject::ParseError, message: be =~ /offset 17/)
		end
		
		it "reports the offset of an unterminated quoted-string" do
			error = nil
			
			begin
				subject.parse('Digest realm="unclosed')
			rescue subject::ParseError => parse_error
				error = parse_error
			end
			
			expect(error).not.to be_nil
			expect(error.offset).to be == 13
			expect(error.value).to be == 'Digest realm="unclosed'
		end
		
		it "rejects an empty value" do
			expect do
				subject.parse("")
			end.to raise_exception(subject::ParseError, message: be =~ /Expected authentication scheme/)
		end
		
		it "rejects a missing scheme after a comma" do
			expect do
				subject.parse("Digest a=b,,")
			end.to raise_exception(subject::ParseError, message: be =~ /Expected authentication scheme at offset 11/)
		end
		
		it "points at the exact location of the error in the detailed message" do
			error = nil
			
			begin
				subject.parse('Digest realm="x" garbage')
			rescue subject::ParseError => parse_error
				error = parse_error
			end
			
			expect(error.detailed_message).to be(:include?, "                 ^")
		end
	end
	
	with "encoding" do
		it "serializes challenges to a comma-separated value" do
			header = subject.new([
				subject::Challenge.new("Digest", nil, [["realm", "a, b"]]),
				subject::Challenge.new("Basic", "abc=="),
			])
			
			expect(header.to_s).to be == 'Digest realm="a, b", Basic abc=='
		end
		
		it "appends challenges from raw values" do
			header = subject.parse("Digest a=1")
			header << "Bearer b=2"
			
			expect(header.map(&:scheme)).to be == ["Digest", "Bearer"]
		end
	end
	
	with "headers integration" do
		it "parses www-authenticate headers using the default policy" do
			headers = Protocol::HTTP::Headers.new
			headers.add("www-authenticate", 'Digest realm="test"')
			headers.add("www-authenticate", "Bearer")
			
			value = headers["www-authenticate"]
			
			expect(value).to be_a(subject)
			expect(value.map(&:scheme)).to be == ["Digest", "Bearer"]
		end
	end
end
