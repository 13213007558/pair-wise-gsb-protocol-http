# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/link"
require "protocol/http/headers"
require "sus"

describe Protocol::HTTP::Header::Link do
	it "classifies parse errors as invalid headers" do
		expect(subject::ParseError.new).to be_a(Protocol::HTTP::InvalidHeaderError)
	end
	
	let(:header) {subject.parse(description)}
	
	with "empty header" do
		let(:header) {subject.new}
		
		it "should be empty" do
			expect(header.to_s).to be == ""
		end
		
		it "should return empty links" do
			expect(header.links).to be == []
		end
	end
	
	with "</style.css>; rel=stylesheet" do
		it "can parse target and relation" do
			links = header.links
			expect(links.size).to be == 1
			expect(links.first.target).to be == "/style.css"
			expect(links.first.relations).to be == ["stylesheet"]
			expect(links.first).to be(:relation?, "stylesheet")
		end
	end
	
	with '</a,b.css>; title="x, y"; rel=alternate' do
		it "does not split on commas inside quoted strings" do
			links = header.links
			expect(links.size).to be == 1
			expect(links.first.target).to be == "/a,b.css"
			expect(links.first.title).to be == "x, y"
		end
	end
	
	with '</a>; title="one, two", </b>; rel=next' do
		it "splits multiple links on commas outside quoted strings" do
			links = header.links
			expect(links.size).to be == 2
			expect(links[0].target).to be == "/a"
			expect(links[0].title).to be == "one, two"
			expect(links[1].target).to be == "/b"
			expect(links[1].relations).to be == ["next"]
		end
	end
	
	with '</a>; title="say \"hi, there\""' do
		it "handles escaped quotes and commas inside quoted strings" do
			links = header.links
			expect(links.size).to be == 1
			expect(links.first.title).to be == 'say "hi, there"'
		end
	end
	
	with '</page-2>; rel="next prev"' do
		it "keeps multiple relation types on a single link" do
			links = header.links
			expect(links.size).to be == 1
			expect(links.first.relations).to be == ["next", "prev"]
			expect(links.first).to be(:relation?, "prev")
		end
	end
	
	with "</a>; rel=first; rel=second" do
		it "uses the first occurrence of a duplicate parameter" do
			links = header.links
			expect(links.first.relations).to be == ["first"]
		end
	end
	
	with "</a>; rel=help; foo=bar; flag" do
		it "preserves uninterpreted extension parameters" do
			link = header.links.first
			expect(link["foo"]).to be == "bar"
			expect(link.parameters.keys).to be == ["rel", "foo", "flag"]
			expect(link.parameters["flag"]).to be_nil
		end
		
		it "round-trips extension parameters" do
			link = header.links.first
			expect(link.to_s).to be == "</a>;rel=help;foo=bar;flag"
			expect(subject.parse(link.to_s).links.first).to be == link
		end
	end
	
	with "</a>; rel=stylesheet; =broken" do
		it "ignores syntactically invalid parameters" do
			links = header.links
			expect(links.first.relations).to be == ["stylesheet"]
		end
	end
	
	with "not-a-link" do
		it "raises ParseError for malformed link values" do
			expect do
				header.links
			end.to raise_exception(subject::ParseError)
		end
	end
	
	with "title* extended notation" do
		with "</kapitel-2>; title*=UTF-8'de'N%c3%a4chstes%20Kapitel" do
			it "decodes charset and language tagged titles" do
				link = header.links.first
				expect(link.title).to be == "Nächstes Kapitel"
				
				extended_title = link.extended_title
				expect(extended_title.charset).to be == "UTF-8"
				expect(extended_title.language).to be == "de"
				expect(extended_title.value).to be == "Nächstes Kapitel"
			end
		end
		
		with "</hello>; title*=UTF-8''%e4%bd%a0%e5%a5%bd" do
			it "decodes non-ASCII titles" do
				link = header.links.first
				expect(link.title).to be == "你好"
				expect(link.extended_title.language).to be_nil
			end
		end
		
		with "</rates>; title*=ISO-8859-1'en'%a3%20rates" do
			it "transcodes non-UTF-8 charsets" do
				link = header.links.first
				expect(link.title).to be == "£ rates"
				expect(link.title.encoding).to be == Encoding::UTF_8
			end
		end
		
		with "</a>; title=plain; title*=UTF-8''N%c3%a4chstes" do
			it "prefers title* over title" do
				link = header.links.first
				expect(link.title).to be == "Nächstes"
			end
		end
	end
	
	with "context and resolution" do
		with "</page-2>; rel=next" do
			it "uses the request URI as the default context" do
				link = header.links.first
				expect(link.context("http://example.com/a/b").to_s).to be == "http://example.com/a/b"
				expect(link.resolve("http://example.com/a/b").to_s).to be == "http://example.com/page-2"
			end
			
			it "resolves relative targets against the request URI" do
				link = header.links.first.with(target: "page-2")
				expect(link.resolve("http://example.com/a/b").to_s).to be == "http://example.com/a/page-2"
			end
		end
		
		with %{<other>; anchor="../base"} do
			it "resolves a relative anchor against the request URI" do
				link = header.links.first
				expect(link.context("http://example.com/a/b/c").to_s).to be == "http://example.com/a/base"
				expect(link.resolve("http://example.com/a/b/c").to_s).to be == "http://example.com/a/other"
			end
		end
		
		with %{<other>; anchor="http://other.example/root/"} do
			it "uses an absolute anchor as the context" do
				link = header.links.first
				expect(link.context("http://example.com/a").to_s).to be == "http://other.example/root/"
				expect(link.resolve("http://example.com/a").to_s).to be == "http://other.example/root/other"
			end
		end
		
		with "http://absolute.example/resource" do
			let(:header) {subject.parse("<http://absolute.example/resource>")}
			
			it "resolves absolute targets without a request URI" do
				link = header.links.first
				expect(link.resolve.to_s).to be == "http://absolute.example/resource"
			end
		end
	end
	
	with "#<<" do
		let(:header) {subject.new}
		
		it "can add links from strings" do
			header << "</a>; rel=help"
			header << '</b>; title="x,y", </c>; rel=next'
			
			expect(header.size).to be == 3
			
			links = header.links
			expect(links[0].target).to be == "/a"
			expect(links[1].target).to be == "/b"
			expect(links[1].title).to be == "x,y"
			expect(links[2].target).to be == "/c"
		end
	end
	
	with Protocol::HTTP::Headers do
		it "parses link headers according to policy" do
			headers = Protocol::HTTP::Headers.new
			headers.add("link", "</a>; rel=help")
			headers.add("link", '</b>; title="x,y"')
			
			value = headers["link"]
			expect(value).to be_a(Protocol::HTTP::Header::Link)
			
			links = value.links
			expect(links.size).to be == 2
			expect(links[0].target).to be == "/a"
			expect(links[1].title).to be == "x,y"
		end
	end
end

describe Protocol::HTTP::Header::Link::Entry do
	let(:entry) {subject.parse("</a>; rel=help; title=Help")}
	
	it "can change a single parameter" do
		updated = entry.with(rel: "preload")
		
		expect(updated.relations).to be == ["preload"]
		expect(updated.title).to be == "Help"
		expect(updated.target).to be == "/a"
		
		# The original entry is unchanged:
		expect(entry.relations).to be == ["help"]
	end
	
	it "can change the target" do
		updated = entry.with(target: "/b")
		expect(updated.target).to be == "/b"
		expect(updated.relations).to be == ["help"]
	end
	
	it "can remove a parameter" do
		updated = entry.with(title: nil)
		expect(updated.title).to be_nil
		expect(updated.parameters).not.to be(:key?, "title")
	end
	
	it "can add an extension parameter" do
		updated = entry.with(anchor: "/context")
		expect(updated.anchor).to be == "/context"
		expect(updated.to_s).to be == %{</a>;rel=help;title=Help;anchor="/context"}
	end
	
	it "can add a valueless parameter" do
		updated = entry.with(flag: true)
		expect(updated.parameters["flag"]).to be_nil
		expect(updated.to_s).to be(:end_with?, ";flag")
	end
	
	it "can set multiple relation types from an array" do
		updated = entry.with(rel: ["next", "prev"])
		expect(updated.relations).to be == ["next", "prev"]
		expect(updated.to_s).to be(:include?, %{rel="next prev"})
	end
	
	it "can set an extended title parameter" do
		updated = entry.with(:"title*" => "UTF-8''N%c3%a4chstes")
		expect(updated.title).to be == "Nächstes"
	end
	
	it "can reconstruct a header from modified entries" do
		header = Protocol::HTTP::Header::Link.parse("</a>; rel=help, </b>; rel=next")
		
		entries = header.links
		entries[0] = entries[0].with(rel: "stylesheet")
		
		updated = Protocol::HTTP::Header::Link.new(entries)
		links = updated.links
		expect(links[0].relations).to be == ["stylesheet"]
		expect(links[1].relations).to be == ["next"]
	end
	
	it "serializes parameters requiring quotes" do
		entry = subject.new("/a", {"title" => "a, b"})
		expect(entry.to_s).to be == %{</a>;title="a, b"}
	end
end
