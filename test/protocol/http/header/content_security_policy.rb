# frozen_string_literal: true

require "protocol/http/headers"

describe Protocol::HTTP::Header::ContentSecurityPolicy do
	let(:origin) {"https://example.com"}
	
	it "parses a header value into a policy" do
		header = subject.parse("script-src 'self'; default-src https:")
		
		expect(header.size).to be == 1
		expect(header.first.directives).to be == {
			"script-src" => ["'self'"],
			"default-src" => ["https:"],
		}
	end
	
	it "keeps multiple header entries as separate policies" do
		headers = Protocol::HTTP::Headers.new
		headers.add("content-security-policy", "script-src 'self'")
		headers.add("content-security-policy", "script-src https://cdn.example.com")
		
		header = headers["content-security-policy"]
		
		expect(header).to be_a(subject)
		expect(header.size).to be == 2
	end
	
	it "serializes policies back to a header value" do
		header = subject.parse("script-src 'self'")
		
		expect(header.to_s).to be == "script-src 'self'"
	end
	
	it "evaluates a resource load against all policies" do
		header = subject.parse("script-src 'self'")
		header << "script-src https://cdn.example.com"
		
		result = header.evaluate(:script, "https://cdn.example.com/app.js", origin: origin)
		
		expect(result).to be(:blocked?)
		expect(result.verdicts.size).to be == 2
		expect(result.verdicts.map(&:report_only?)).to be == [false, false]
	end
	
	with ".evaluate" do
		it "combines enforcing and report-only headers" do
			enforcing = subject.parse("script-src 'self'")
			report_only = Protocol::HTTP::Header::ContentSecurityPolicyReportOnly.parse("script-src 'none'")
			
			result = subject.evaluate([enforcing, report_only], :script, "https://example.com/app.js", origin: origin)
			
			expect(result).to be(:allowed?)
			expect(result.enforcing.size).to be == 1
			expect(result.report_only.size).to be == 1
			expect(result.report_only.first).to be(:blocked?)
		end
	end
end

describe Protocol::HTTP::Header::ContentSecurityPolicyReportOnly do
	it "is report-only" do
		header = subject.parse("script-src 'none'")
		
		expect(header).to be(:report_only?)
		
		result = header.evaluate(:script, "https://example.com/app.js")
		
		expect(result).to be(:allowed?)
		expect(result.verdicts.first).to have_attributes(
			allowed?: be == false,
			report_only?: be == true,
		)
	end
	
	it "is parsed from content-security-policy-report-only headers" do
		headers = Protocol::HTTP::Headers.new
		headers.add("content-security-policy-report-only", "script-src 'none'")
		
		expect(headers["content-security-policy-report-only"]).to be_a(subject)
	end
end
