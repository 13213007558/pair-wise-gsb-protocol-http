# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/header/link"
require "sus"

describe Protocol::HTTP::Header::Link do
	let(:header) {subject.parse(description)}
	
	it "classifies parse errors as invalid headers" do
		expect(subject::ParseError.new).to be_a(Protocol::HTTP::InvalidHeaderError)
	end
	
	it "is not allowed in trailers" do
		expect(subject.trailer?).to be == false
	end
	
	with "</style.css>; rel=stylesheet" do
		it "parses the target" do
			expect(header.size).to be == 1
			expect(header.entries.first.target).to be == "/style.css"
		end
		
		it "parses the relation set" do
			expect(header.entries.first.relations).to be == ["stylesheet"]
		end
		
		it "answers to relation queries" do
			expect(header.entries.first).to be(:relation?, "STYLESHEET")
			expect(header.entries.first).not.to be(:relation?, "preload")
		end
		
		it "can look up entries by relation" do
			expect(header["stylesheet"].map(&:target)).to be == ["/style.css"]
			expect(header["preload"]).to be(:empty?)
		end
	end
	
	with "</page>; rel=\"next prefetch\"" do
		it "collects multiple relations into a single target" do
			entry = header.entries.first
			
			expect(header.size).to be == 1
			expect(entry.target).to be == "/page"
			expect(entry.relations).to be == ["next", "prefetch"]
		end
		
		it "normalizes relations to lower case" do
			expect(header.entries.first.relations).to be(:all?, &:lowercase?)
		end
	end
	
	with "</a>, </b>, </c>" do
		it "parses multiple links" do
			expect(header.entries.map(&:target)).to be == ["/a", "/b", "/c"]
		end
	end
	
	with "</a>; title=\"Hello, World\", </b>; rel=next" do
		it "does not split on commas inside quoted strings" do
			expect(header.size).to be == 2
			expect(header.entries.first.title).to be == "Hello, World"
			expect(header.entries.last.target).to be == "/b"
		end
	end
	
	with "</a>; title=\"semicolon; inside\", </b>" do
		it "does not split parameters on semicolons inside quoted strings" do
			expect(header.size).to be == 2
			expect(header.entries.first.title).to be == "semicolon; inside"
			expect(header.entries.last.target).to be == "/b"
		end
	end
	
	with "escaped quotes" do
		let(:header) {subject.parse(%(</a>; title="she said \\"hi\\"", </b>))}
		
		it "unquotes escaped quotes without splitting the entry" do
			expect(header.size).to be == 2
			expect(header.entries.first.title).to be == 'she said "hi"'
			expect(header.entries.last.target).to be == "/b"
		end
	end
	
	with "</a>; rel=first; rel=second" do
		it "uses the first occurrence of rel" do
			expect(header.entries.first.relations).to be == ["first"]
		end
	end
	
	with "</a>; rel=\"a a b\"" do
		it "deduplicates relations while preserving order" do
			expect(header.entries.first.relations).to be == ["a", "b"]
		end
	end
	
	with "</a>; title=\"First\"; title=\"Second\"" do
		it "uses the first occurrence of title" do
			expect(header.entries.first.title).to be == "First"
		end
	end
	
	with "</a>; crossorigin; type=text/html; custom=\"x;y\"" do
		it "preserves uninterpreted extension parameters" do
			parameters = header.entries.first.parameters
			
			expect(parameters["crossorigin"]).to be == true
			expect(parameters["type"]).to be == "text/html"
			expect(parameters["custom"]).to be == "x;y"
		end
		
		it "keeps the first occurrence of an extension parameter" do
			header2 = subject.parse('</a>; type=text/html; type=text/plain')
			expect(header2.entries.first.parameters["type"]).to be == "text/html"
		end
	end
	
	with "</a>; anchor=\"/blog/index\"" do
		it "exposes the anchor" do
			expect(header.entries.first.anchor).to be == "/blog/index"
		end
	end
	
	with "</a>; anchor=<../relative>" do
		it "parses angle-bracketed anchors" do
			expect(header.entries.first.anchor).to be == "../relative"
		end
	end
	
	with "title*" do
		let(:header) do
			subject.parse(%{</a>; title="Fallback"; title*=UTF-8'en'%E2%9C%A8})
		end
		
		it "decodes the extended title" do
			expect(header.entries.first.title_localized.value).to be == "\u2728"
		end
		
		it "captures the charset and language" do
			localized = header.entries.first.title_localized
			
			expect(localized.charset).to be == "utf-8"
			expect(localized.language).to be == "en"
		end
		
		it "prefers the localized title over the plain title" do
			expect(header.entries.first.title).to be == "\u2728"
		end
	end
	
	with "non-ASCII title*" do
		let(:header) do
			subject.parse(%{</a>; title*=UTF-8'zh-CN'%E4%B8%AD%E6%96%87})
		end
		
		it "decodes non-ASCII titles with a language tag" do
			localized = header.entries.first.title_localized
			
			expect(localized.value).to be == "\u4E2D\u6587"
			expect(localized.language).to be == "zh-CN"
			expect(localized.value.encoding).to be == Encoding::UTF_8
		end
	end
	
	with "title*=UTF-8''%ZZ" do
		let(:header) {subject.parse("</a>; title*=UTF-8''%ZZ")}
		
		it "ignores uninterpretable extended values" do
			expect(header.entries.first.title_localized).to be_nil
			expect(header.entries.first.title).to be_nil
		end
	end
	
	with "not-a-link" do
		it "raises a parse error for a missing target" do
			expect do
				header.entries
			end.to raise_exception(subject::ParseError)
		end
	end
	
	with "resolution" do
		let(:base) {"https://example.com/blog/2026/index"}
		let(:header) {subject.parse(description)}
		
		with "<../style.css>; rel=stylesheet" do
			it "resolves the target against the request URI" do
				expect(header.resolve(base)).to be == ["https://example.com/blog/style.css"]
			end
		end
		
		with "<next.html>; rel=next; anchor=\"../parent/\"" do
			it "resolves relative targets against a relative anchor" do
				expect(header.resolve(base)).to be == ["https://example.com/blog/parent/next.html"]
			end
		end
		
		with "<#section>" do
			it "resolves fragment-only references against the request URI" do
				expect(header.resolve(base)).to be == ["https://example.com/blog/2026/index#section"]
			end
		end
		
		with "<https://other.test/a>; anchor=\"https://anchor.test/base\"" do
			it "uses an absolute anchor as the link context" do
				expect(header.resolve(base)).to be == ["https://other.test/a"]
			end
		end
		
		with "a request-like object" do
			let(:request) {Struct.new(:scheme, :authority, :path).new("https", "example.com", "/blog/index")}
			
			it "builds the request URI from the object" do
				link = subject.parse("<css/app.css>; rel=stylesheet")
				expect(link.resolve(request)).to be == ["https://example.com/blog/css/app.css"]
			end
		end
		
		it "requires a request URI" do
			expect do
				subject.parse("</a>; rel=next").resolve
			end.to raise_exception(ArgumentError)
		end
	end
	
	with "serialization" do
		it "round trips a structured link" do
			raw = '</a>; rel="next prefetch"; title="Hello, World"; crossorigin'
			expect(subject.parse(raw).to_s).to be == raw
		end
		
		it "quotes titles when re-serializing" do
			header = subject.parse("</a>; rel=next; title=plain")
			expect(header.to_s).to be == '</a>; rel="next"; title="plain"'
		end
	end
	
	with "construction" do
		it "can construct a link from entries" do
			entry = subject::Entry.new("/a", ["next"])
			header = subject.new([entry])
			
			expect(header.size).to be == 1
			expect(header.to_s).to be == '</a>; rel="next"'
		end
		
		it "can append raw link values" do
			header = subject.new
			header << '</a>; rel=next, </b>; rel=prev'
			
			expect(header.entries.map(&:target)).to be == ["/a", "/b"]
		end
		
		it "coerces an array of raw values" do
			header = subject.coerce(["</a>; rel=next", "</b>; rel=prev"])
			expect(header.size).to be == 2
		end
	end
	
	with "modifying a single parameter" do
		let(:header) {subject.parse('</a>; rel=next; crossorigin; type=text/html')}
		let(:entry) {header.entries.first}
		
		it "returns a copy with a changed extension parameter" do
			updated = entry.with_parameter("type", "text/css")
			
			expect(updated.parameters["type"]).to be == "text/css"
			expect(entry.parameters["type"]).to be == "text/html"
			expect(updated).not.to be_equal(entry)
		end
		
		it "can change the relation set without splitting the target" do
			updated = entry.with_parameter(:rel, ["prev", "edit"])
			
			expect(updated.target).to be == "/a"
			expect(updated.relations).to be == ["prev", "edit"]
			expect(entry.relations).to be == ["next"]
		end
		
		it "can remove a parameter" do
			updated = entry.with_parameter("crossorigin", nil)
			
			expect(updated.parameters).not.to be(:key?, "crossorigin")
			expect(entry.parameters["crossorigin"]).to be == true
		end
		
		it "can change the anchor" do
			updated = entry.with_parameter("anchor", "/other")
			
			expect(updated.anchor).to be == "/other"
			expect(entry.anchor).to be_nil
		end
		
		it "can mutate in place with set_parameter!" do
			entry.set_parameter!("type", "text/css")
			
			expect(entry.parameters["type"]).to be == "text/css"
		end
	end
end

describe Protocol::HTTP::Header::Link::LocalizedValue do
	it "serializes to an RFC 8187 ext-value" do
		value = subject.new("\u2728", "en")
		expect(value.to_s).to be == "UTF-8'en'%E2%9C%A8"
	end
	
	it "round trips non-ASCII text" do
		value = subject.new("\u4E2D\u6587", "zh-CN")
		raw = value.to_s
		parsed = Protocol::HTTP::Header::Link::Entry.send(:parse_extended_value, raw)
		
		expect(parsed.value).to be == "\u4E2D\u6587"
		expect(parsed.language).to be == "zh-CN"
	end
	
	it "supports values without a language tag" do
		value = subject.new("cafe", nil)
		expect(value.to_s).to be == "UTF-8''cafe"
	end
end
