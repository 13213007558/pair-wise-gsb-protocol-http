# frozen_string_literal: true

require "protocol/http/content_security_policy"

describe Protocol::HTTP::ContentSecurityPolicy do
	Policy = Protocol::HTTP::ContentSecurityPolicy::Policy
	
	let(:origin) {"https://example.com"}
	
	describe Policy do
		it "parses directives into source lists" do
			policy = Policy.parse("script-src 'self' https://cdn.example.com; default-src 'none'")
			
			expect(policy.directives).to be == {
				"script-src" => ["'self'", "https://cdn.example.com"],
				"default-src" => ["'none'"],
			}
		end
		
		it "preserves unknown directives" do
			policy = Policy.parse("script-src 'self'; x-custom-directive foo bar")
			
			expect(policy["x-custom-directive"]).to be == ["foo", "bar"]
		end
		
		it "ignores repeated directives after the first occurrence" do
			policy = Policy.parse("script-src 'self'; script-src https:")
			
			expect(policy["script-src"]).to be == ["'self'"]
		end
		
		it "round-trips to a serialized policy" do
			policy = Policy.parse("script-src 'self'; default-src https:")
			
			expect(policy.to_s).to be == "script-src 'self'; default-src https:"
		end
	end
	
	with "default-src fallback" do
		let(:policy) {Policy.parse("default-src 'none'; img-src https:")}
		
		it "uses the specific directive when present" do
			verdict = policy.evaluate(:img, "https://cdn.example.com/logo.png")
			
			expect(verdict).to have_attributes(
				allowed?: be == true,
				directive: be == "img-src",
				matched_source: be == "https:",
			)
		end
		
		it "falls back to default-src when the specific directive is absent" do
			verdict = policy.evaluate(:script, "https://cdn.example.com/app.js")
			
			expect(verdict).to have_attributes(
				allowed?: be == false,
				directive: be == "default-src",
				matched_source: be == nil,
			)
		end
		
		it "does not restrict resource types without any applicable directive" do
			policy = Policy.parse("img-src https:")
			verdict = policy.evaluate(:script, "https://cdn.example.com/app.js")
			
			expect(verdict).to have_attributes(
				allowed?: be == true,
				directive: be == nil,
			)
		end
	end
	
	with "source expressions" do
		it "matches 'self' against the origin" do
			policy = Policy.parse("script-src 'self'")
			
			expect(policy.allows?(:script, "https://example.com/app.js", origin: origin)).to be == true
			expect(policy.allows?(:script, "https://cdn.example.com/app.js", origin: origin)).to be == false
		end
		
		it "matches scheme sources, including upgrades" do
			policy = Policy.parse("img-src http: data:")
			
			expect(policy.allows?(:img, "http://cdn.example.com/logo.png")).to be == true
			expect(policy.allows?(:img, "https://cdn.example.com/logo.png")).to be == true
			expect(policy.allows?(:img, "data:image/png;base64,AAAA")).to be == true
			expect(policy.allows?(:img, "ftp://cdn.example.com/logo.png")).to be == false
		end
		
		it "matches host sources with wildcards and ports" do
			policy = Policy.parse("script-src *.example.com example.org:8443")
			
			expect(policy.allows?(:script, "https://cdn.example.com/app.js")).to be == true
			expect(policy.allows?(:script, "https://example.com/app.js")).to be == true
			expect(policy.allows?(:script, "https://example.org:8443/app.js")).to be == true
			expect(policy.allows?(:script, "https://example.org/app.js")).to be == false
			expect(policy.allows?(:script, "https://other.net/app.js")).to be == false
		end
		
		it "matches nonces and hashes" do
			policy = Policy.parse("script-src 'nonce-abc123' 'sha256-xyz'")
			
			expect(policy.allows?(:script, nil, nonce: "abc123", inline: true)).to be == true
			expect(policy.allows?(:script, nil, hashes: ["sha256-xyz"], inline: true)).to be == true
			expect(policy.allows?(:script, nil, nonce: "wrong", inline: true)).to be == false
		end
		
		it "ignores 'unsafe-inline' when a nonce or hash is present" do
			policy = Policy.parse("script-src 'unsafe-inline' 'nonce-abc123'")
			
			expect(policy.allows?(:script, nil, inline: true)).to be == false
			expect(policy.allows?(:script, nil, nonce: "abc123", inline: true)).to be == true
		end
		
		it "treats 'none' as matching nothing" do
			policy = Policy.parse("script-src 'none'")
			
			expect(policy.allows?(:script, "https://example.com/app.js", origin: origin)).to be == false
		end
	end
	
	with "strict-dynamic" do
		let(:policy) {Policy.parse("script-src 'nonce-abc123' 'strict-dynamic' https://cdn.example.com")}
		
		it "ignores host source expressions" do
			verdict = policy.evaluate(:script, "https://cdn.example.com/app.js")
			
			expect(verdict).to have_attributes(
				allowed?: be == false,
				matched_source: be == nil,
			)
		end
		
		it "allows scripts with a matching nonce" do
			verdict = policy.evaluate(:script, "https://cdn.example.com/app.js", nonce: "abc123")
			
			expect(verdict).to have_attributes(
				allowed?: be == true,
				matched_source: be == "'nonce-abc123'",
			)
		end
	end
	
	with "multiple policies" do
		# Two enforcing policies: one allows 'self', the other allows the CDN. If the source lists were merged into a single policy, both URLs below would be allowed. With correct intersection semantics, a resource must be allowed by *every* policy, so both are blocked.
		let(:policies) do
			[
				Policy.parse("script-src 'self'"),
				Policy.parse("script-src https://cdn.example.com"),
			]
		end
		
		it "intersects policies rather than merging source lists" do
			result = subject.evaluate(policies, :script, "https://cdn.example.com/app.js", origin: origin)
			
			expect(result).to be(:blocked?)
			expect(result.verdicts[0]).to have_attributes(allowed?: be == false, directive: be == "script-src")
			expect(result.verdicts[1]).to have_attributes(allowed?: be == true, matched_source: be == "https://cdn.example.com")
		end
		
		it "blocks 'self' when another policy does not allow it" do
			result = subject.evaluate(policies, :script, "https://example.com/app.js", origin: origin)
			
			expect(result).to be(:blocked?)
			expect(result.verdicts[0]).to be(:allowed?)
			expect(result.verdicts[1]).to be(:blocked?)
		end
		
		it "allows a resource allowed by every policy" do
			policies = [
				Policy.parse("script-src 'self' https://cdn.example.com"),
				Policy.parse("script-src https://cdn.example.com"),
			]
			
			result = subject.evaluate(policies, :script, "https://cdn.example.com/app.js", origin: origin)
			
			expect(result).to be(:allowed?)
		end
	end
	
	with "report-only policies" do
		it "does not change the outcome" do
			enforcing = [Policy.parse("script-src 'self'")]
			report_only = [Policy.parse("script-src 'none'")]
			
			result = subject.evaluate(enforcing, :script, "https://example.com/app.js", origin: origin, report_only: report_only)
			
			expect(result).to be(:allowed?)
			expect(result.report_only.first).to have_attributes(
				allowed?: be == false,
				report_only?: be == true,
			)
		end
		
		it "cannot rescue a resource blocked by an enforcing policy" do
			enforcing = [Policy.parse("script-src 'none'")]
			report_only = [Policy.parse("script-src *")]
			
			result = subject.evaluate(enforcing, :script, "https://cdn.example.com/app.js", report_only: report_only)
			
			expect(result).to be(:blocked?)
			expect(result.report_only.first).to be(:allowed?)
		end
	end
end
