# frozen_string_literal: true

require "protocol/http/header/content_security_policy"
require "protocol/http/headers"

describe Protocol::HTTP::Header::ContentSecurityPolicy do
	let(:policy) {subject::Policy.parse(description)}
	let(:csp) {Protocol::HTTP::Header::ContentSecurityPolicy}
	
	with "default-src 'self'; script-src 'nonce-abc' https://cdn.example.com; require-trusted-types-for 'script'; upgrade-insecure-requests" do
		it "parses directives and preserves unknown ones" do
			expect(policy.directives.keys).to be == [
				"default-src", "script-src", "require-trusted-types-for", "upgrade-insecure-requests"
			]
			
			expect(policy["require-trusted-types-for"]).to be == ["'script'"]
			expect(policy["upgrade-insecure-requests"]).to be == []
		end
		
		it "round-trips through serialization" do
			expect(policy.to_s).to be == description
		end
	end
	
	with "default-src 'self'" do
		it "falls back to default-src and reports the effective directive" do
			verdict = policy.evaluate("img", "https://example.com/logo.png", origin: "https://example.com")
			
			expect(verdict).to have_attributes(
				directive: be == "default-src",
				source: be == "'self'",
				allowed?: be == true,
			)
		end
		
		it "blocks cross-origin loads" do
			verdict = policy.evaluate("img", "https://cdn.example.com/logo.png", origin: "https://example.com")
			
			expect(verdict).to have_attributes(
				directive: be == "default-src",
				source: be_nil,
				allowed?: be == false,
			)
		end
	end
	
	with "default-src 'none'; script-src 'self'" do
		it "allows scripts from self but blocks everything else" do
			expect(policy.allows?("script", "https://example.com/app.js", origin: "https://example.com")).to be == true
			expect(policy.allows?("img", "https://example.com/logo.png", origin: "https://example.com")).to be == false
		end
	end
	
	with "img-src https: data:" do
		it "matches scheme sources" do
			expect(policy.allows?("img", "https://anything.example/x.png")).to be == true
			expect(policy.allows?("img", "data:image/png;base64,AAAA")).to be == true
			expect(policy.allows?("img", "http://anything.example/x.png")).to be == false
		end
	end
	
	with "img-src *.example.com example.com:8080" do
		it "matches subdomain wildcards" do
			expect(policy.allows?("img", "https://a.example.com/x.png")).to be == true
			expect(policy.allows?("img", "https://example.com/x.png")).to be == false
		end
		
		it "matches explicit ports and requires default ports otherwise" do
			expect(policy.allows?("img", "http://example.com:8080/x.png")).to be == true
			expect(policy.allows?("img", "http://a.example.com:8080/x.png")).to be == false
		end
		
	end
	
	with "img-src https://cdn.example.com/assets/" do
		it "matches path prefixes" do
			expect(policy.allows?("img", "https://cdn.example.com/assets/x.png")).to be == true
			expect(policy.allows?("img", "https://cdn.example.com/other/x.png")).to be == false
		end
	end
	
	with "script-src 'nonce-abc123'" do
		it "allows elements with a matching nonce" do
			verdict = policy.evaluate("script", nil, nonce: "abc123")
			
			expect(verdict).to have_attributes(
				source: be == "'nonce-abc123'",
				allowed?: be == true,
			)
		end
		
		it "blocks elements with a wrong nonce" do
			expect(policy.allows?("script", nil, nonce: "wrong")).to be == false
			expect(policy.allows?("script", nil)).to be == false
		end
	end
	
	with "script-src 'sha256-oniv6hrg65Ozw6o4pWGjWK+G4NHTvFQ1xQmUpaomkHs='" do
		it "allows elements with a matching hash" do
			expect(policy.allows?("script", nil, hashes: ["sha256-oniv6hrg65Ozw6o4pWGjWK+G4NHTvFQ1xQmUpaomkHs="])).to be == true
			expect(policy.allows?("script", nil, hashes: ["sha256-other"])).to be == false
		end
	end
	
	with "script-src 'unsafe-inline'" do
		it "allows inline scripts" do
			expect(policy.allows?("script", nil)).to be == true
		end
	end
	
	with "script-src 'nonce-abc' 'unsafe-inline'" do
		it "ignores 'unsafe-inline' when a nonce or hash is present" do
			expect(policy.allows?("script", nil)).to be == false
			expect(policy.allows?("script", nil, nonce: "abc")).to be == true
		end
	end
	
	with "script-src 'nonce-abc' 'strict-dynamic' https://cdn.example.com 'self'" do
		it "allows any host when the nonce matches" do
			expect(policy.allows?("script", "https://unlisted.example.com/x.js", nonce: "abc", origin: "https://example.com")).to be == true
		end
		
		it "ignores host sources, including 'self', without a matching nonce" do
			expect(policy.allows?("script", "https://cdn.example.com/x.js", origin: "https://example.com")).to be == false
			expect(policy.allows?("script", "https://example.com/x.js", origin: "https://example.com")).to be == false
		end
	end
	
	with "script-src https://cdn.example.com" do
		it "matches host sources normally when 'strict-dynamic' is absent" do
			expect(policy.allows?("script", "https://cdn.example.com/x.js")).to be == true
		end
	end
	
	describe "policy intersection vs merged source lists" do
		# Two separate policies, as delivered by two header entries:
		let(:header) {csp.coerce(["script-src 'self'", "script-src https://cdn.example.com"])}
		
		it "intersects policies instead of merging their source lists" do
			# A naive merge of the source lists would be 'self' + https://cdn.example.com,
			# allowing both of these URLs. Correct CSP semantics intersect the policies,
			# so each URL is blocked by the policy that doesn't list it:
			cdn = header.evaluate("script", "https://cdn.example.com/app.js", origin: "https://example.com")
			expect(cdn.verdicts.map(&:allowed?)).to be == [false, true]
			expect(cdn.allowed?).to be == false
			
			self_hosted = header.evaluate("script", "https://example.com/app.js", origin: "https://example.com")
			expect(self_hosted.verdicts.map(&:allowed?)).to be == [true, false]
			expect(self_hosted.allowed?).to be == false
		end
		
		it "allows loads permitted by every policy" do
			header = csp.coerce(["script-src 'self'", "script-src 'self' https://cdn.example.com"])
			
			result = header.evaluate("script", "https://example.com/app.js", origin: "https://example.com")
			expect(result.verdicts.map(&:allowed?)).to be == [true, true]
			expect(result.allowed?).to be == true
		end
		
		it "reports the effective directive of each policy" do
			header = csp.coerce(["default-src 'none'", "script-src https://cdn.example.com"])
			
			result = header.evaluate("script", "https://cdn.example.com/app.js")
			expect(result.verdicts.map(&:directive)).to be == ["default-src", "script-src"]
			expect(result.allowed?).to be == false
		end
	end
	
	describe "report-only policies" do
		let(:enforcing) {csp.parse("script-src 'self'")}
		let(:report_only) {csp::ReportOnly.parse("script-src https://cdn.example.com")}
		
		it "evaluates report-only policies without changing the result" do
			result = enforcing.evaluate("script", "https://example.com/app.js", origin: "https://example.com", report_only: report_only)
			
			# The report-only policy blocks this load, but the load is still allowed:
			expect(result.report_only.first).to have_attributes(
				allowed?: be == false,
				report_only?: be == true,
			)
			expect(result.allowed?).to be == true
		end
		
		it "does not let report-only policies allow blocked loads" do
			result = enforcing.evaluate("script", "https://cdn.example.com/app.js", origin: "https://example.com", report_only: report_only)
			
			expect(result.report_only.first.allowed?).to be == true
			expect(result.allowed?).to be == false
		end
		
		it "marks its own verdicts as report-only when evaluated standalone" do
			result = report_only.evaluate("script", "https://cdn.example.com/app.js")
			
			expect(result.verdicts.first.report_only?).to be == true
			expect(result.allowed?).to be == true
		end
	end
	
	describe "header integration" do
		let(:headers) {Protocol::HTTP::Headers.new}
		
		it "collects repeated headers as separate policies" do
			headers.add("content-security-policy", "script-src 'self'")
			headers.add("content-security-policy", "script-src https://cdn.example.com")
			
			header = headers["content-security-policy"]
			
			expect(header).to be_a(csp)
			expect(header.size).to be == 2
			expect(header.map(&:class)).to be == [csp::Policy, csp::Policy]
		end
		
		it "parses the report-only variant" do
			headers.add("content-security-policy-report-only", "script-src 'self'")
			
			header = headers["content-security-policy-report-only"]
			
			expect(header).to be_a(csp::ReportOnly)
			expect(header.report_only?).to be == true
		end
	end
end
