# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/link/uri_reference"
require "sus"

describe Protocol::HTTP::Header::Link::URIReference do
	let(:base) {subject.parse("http://a/b/c/d;p?q")}
	
	def resolve(reference)
		subject.parse(reference).resolve(base).to_s
	end
	
	with "#parse" do
		it "extracts the components of an absolute URI" do
			uri = subject.parse("https://example.com:8080/a/b?x=1#frag")
			
			expect(uri.scheme).to be == "https"
			expect(uri.authority).to be == "example.com:8080"
			expect(uri.path).to be == "/a/b"
			expect(uri.query).to be == "x=1"
			expect(uri.fragment).to be == "frag"
			expect(uri).to be(:absolute?)
		end
		
		it "parses relative references without a scheme" do
			uri = subject.parse("../a/b")
			
			expect(uri.scheme).to be_nil
			expect(uri.path).to be == "../a/b"
			expect(uri).not.to be(:absolute?)
		end
	end
	
	with "#resolve" do
		# Normal examples from RFC 3986 §5.4.1:
		it "resolves normal relative references" do
			expect(resolve("g")).to be == "http://a/b/c/g"
			expect(resolve("./g")).to be == "http://a/b/c/g"
			expect(resolve("g/")).to be == "http://a/b/c/g/"
			expect(resolve("/g")).to be == "http://a/g"
			expect(resolve("//g")).to be == "http://g"
		end
		
		it "resolves dot segments" do
			expect(resolve(".")).to be == "http://a/b/c/"
			expect(resolve("..")).to be == "http://a/b/"
			expect(resolve("../g")).to be == "http://a/b/g"
			expect(resolve("../..")).to be == "http://a/"
			expect(resolve("/../g")).to be == "http://a/g"
			expect(resolve("/./g")).to be == "http://a/g"
			expect(resolve("g/../h")).to be == "http://a/b/c/h"
		end
		
		it "resolves queries and fragments" do
			expect(resolve("?y")).to be == "http://a/b/c/d;p?y"
			expect(resolve("g?y")).to be == "http://a/b/c/g?y"
			expect(resolve("#s")).to be == "http://a/b/c/d;p?q#s"
			expect(resolve("g#s/./x")).to be == "http://a/b/c/g#s/./x"
			expect(resolve("")).to be == "http://a/b/c/d;p?q"
		end
		
		it "keeps absolute URIs absolute" do
			expect(resolve("g:h")).to be == "g:h"
			expect(resolve("http:g")).to be == "http:g"
		end
		
		it "accepts a parsed base reference" do
			resolved = subject.parse("g").resolve(base)
			expect(resolved.to_s).to be == "http://a/b/c/g"
		end
	end
end
