# frozen_string_literal: true

require "uri"

module Protocol
	module HTTP
		# Content Security Policy (CSP) parsing and offline evaluation.
		#
		# A server may send several CSP headers, and the combined value alone doesn't tell you why a resource was blocked. This module parses each policy separately and evaluates a resource load (resource type, URL, nonce/hash context) against every policy, returning a per-policy verdict including the directive that actually applied (after default-src fallback) and the source expression that matched.
		#
		# Multiple enforcing policies are combined with intersection semantics: a resource must be allowed by *every* enforcing policy. Report-only policies are evaluated for visibility but never change the outcome.
		module ContentSecurityPolicy
			# Directive fallback chain, e.g. script-src falls back to default-src:
			FALLBACK = {
				"script-src-elem" => "script-src",
				"script-src-attr" => "script-src",
				"script-src" => "default-src",
				"style-src-elem" => "style-src",
				"style-src-attr" => "style-src",
				"style-src" => "default-src",
				"worker-src" => "child-src",
				"frame-src" => "child-src",
				"child-src" => "default-src",
				"img-src" => "default-src",
				"font-src" => "default-src",
				"connect-src" => "default-src",
				"media-src" => "default-src",
				"object-src" => "default-src",
				"manifest-src" => "default-src",
				"prefetch-src" => "default-src",
			}
			
			# Resource types mapped to their fetch directives:
			RESOURCE_TYPES = {
				script: "script-src",
				style: "style-src",
				img: "img-src",
				font: "font-src",
				connect: "connect-src",
				media: "media-src",
				object: "object-src",
				frame: "frame-src",
				worker: "worker-src",
				manifest: "manifest-src",
				prefetch: "prefetch-src",
			}
			
			# Default ports used for source-expression port matching:
			DEFAULT_PORTS = {
				"http" => 80,
				"https" => 443,
				"ws" => 80,
				"wss" => 443,
			}
			
			NONCE_PATTERN = /\A'nonce-(.+)'\z/
			HASH_PATTERN = /\A'(sha256|sha384|sha512)-(.+)'\z/
			HOST_SOURCE_PATTERN = %r{\A(?:([a-zA-Z][a-zA-Z0-9+.-]*)://)?(\*\.)?([a-zA-Z0-9._-]+)(?::(\d+))?(/[^\s]*)?\z}
			
			# Evaluate a resource load against a set of policies.
			#
			# @parameter policies [Array(Policy)] Enforcing policies — the resource must be allowed by all of them (intersection semantics).
			# @parameter report_only [Array(Policy)] Report-only policies — evaluated and reported, but never affect the outcome.
			# @parameter resource_type [Symbol] e.g. :script, :style, :img, ...
			# @parameter url [String | Nil] The URL of the resource, or nil for inline resources.
			# @parameter nonce [String | Nil] The nonce of the element, if any.
			# @parameter hashes [Array(String)] Content hashes, e.g. "sha256-...", if any.
			# @parameter origin [String | Nil] The origin of the containing document, used for 'self' matching.
			# @parameter inline [Boolean] Whether the resource is inline, e.g. an inline <script> block.
			# @returns [Result] The combined result, with one verdict per policy.
			def self.evaluate(policies, resource_type, url = nil, report_only: [], **context)
				verdicts = policies.map{|policy| policy.evaluate(resource_type, url, report_only: false, **context)}
				verdicts += report_only.map{|policy| policy.evaluate(resource_type, url, report_only: true, **context)}
				
				Result.new(verdicts)
			end
			
			# A single parsed content security policy.
			class Policy
				# Parse a serialized policy into directives. Unknown directives are preserved. If a directive is specified more than once, the first occurrence wins and subsequent occurrences are ignored.
				#
				# @parameter value [String] The serialized policy, e.g. "script-src 'self'; default-src https:".
				# @returns [Policy]
				def self.parse(value)
					directives = {}
					
					value.to_s.split(";").each do |directive|
						name, *sources = directive.strip.split(/\s+/)
						
						if name && !name.empty?
							directives[name.downcase] ||= sources
						end
					end
					
					self.new(directives)
				end
				
				def initialize(directives = {})
					@directives = directives
				end
				
				# All directives, including unknown ones, as a hash of directive name to source list.
				attr :directives
				
				def [](name)
					@directives[name]
				end
				
				def to_s
					@directives.map{|name, sources| [name, *sources].join(" ")}.join("; ")
				end
				
				# The directive that actually applies to the given fetch directive, following the fallback chain (e.g. script-src falls back to default-src).
				#
				# @parameter name [String] The fetch directive name, e.g. "script-src".
				# @returns [Tuple(String, Array(String)) | Nil] The effective directive name and its source list, or nil if the policy does not restrict the resource.
				def effective_directive(name)
					while name
						if sources = @directives[name]
							return name, sources
						end
						
						name = FALLBACK[name]
					end
					
					return nil
				end
				
				# Evaluate a resource load against this policy.
				#
				# @parameter resource_type [Symbol] e.g. :script, :style, :img, ...
				# @parameter url [String | Nil] The URL of the resource, or nil for inline resources.
				# @parameter nonce [String | Nil] The nonce of the element, if any.
				# @parameter hashes [Array(String)] Content hashes, e.g. "sha256-...", if any.
				# @parameter origin [String | Nil] The origin of the containing document, used for 'self' matching.
				# @parameter inline [Boolean] Whether the resource is inline.
				# @parameter report_only [Boolean] Whether this policy is report-only.
				# @returns [Verdict]
				def evaluate(resource_type, url = nil, nonce: nil, hashes: [], origin: nil, inline: false, report_only: false)
					directive_name = RESOURCE_TYPES.fetch(resource_type.to_sym, resource_type.to_s)
					
					if effective = effective_directive(directive_name)
						effective_name, sources = effective
						matched = match_source_list(sources, url: url, nonce: nonce, hashes: hashes, origin: origin, inline: inline)
						
						Verdict.new(policy: self, directive: effective_name, matched_source: matched, allowed: !matched.nil?, report_only: report_only)
					else
						# The policy does not restrict this resource type:
						Verdict.new(policy: self, directive: nil, matched_source: nil, allowed: true, report_only: report_only)
					end
				end
				
				# Whether this policy allows the given resource load.
				#
				# @returns [Boolean]
				def allows?(...)
					evaluate(...).allowed?
				end
				
				private
				
				# Find the source expression that matches the resource, or nil if none match.
				def match_source_list(sources, url:, nonce:, hashes:, origin:, inline:)
					# 'none' matches nothing; when combined with other source expressions it is ignored:
					sources = sources - ["'none'"]
					return nil if sources.empty?
					
					# When a nonce or hash is present, 'unsafe-inline' is ignored:
					nonces_and_hashes = sources.any?{|source| NONCE_PATTERN.match?(source) or HASH_PATTERN.match?(source)}
					
					# When 'strict-dynamic' is present, host and scheme source expressions are ignored:
					strict_dynamic = sources.include?("'strict-dynamic'")
					
					sources.each do |source|
						if matched = match_source(source, url: url, nonce: nonce, hashes: hashes, origin: origin, inline: inline, nonces_and_hashes: nonces_and_hashes, strict_dynamic: strict_dynamic)
							return matched
						end
					end
					
					return nil
				end
				
				# @returns [String | Nil] The source expression if it matches, otherwise nil.
				def match_source(source, url:, nonce:, hashes:, origin:, inline:, nonces_and_hashes:, strict_dynamic:)
					case source
					when NONCE_PATTERN
						return source if nonce && $1 == nonce
					when HASH_PATTERN
						return source if hashes.include?("#{$1}-#{$2}")
					when "'unsafe-inline'"
						return source if inline && !nonces_and_hashes
					when "'self'"
						unless strict_dynamic
							return source if url && origin && self_match?(url, origin)
						end
					when "'strict-dynamic'", "'unsafe-eval'", "'unsafe-hashes'", "'report-sample'", "'unsafe-allow-redirects'"
						# These keywords don't directly match a resource.
					else
						unless strict_dynamic
							return source if url && url_source_match?(source, url, origin)
						end
					end
					
					return nil
				end
				
				def self_match?(url, origin)
					url_uri = parse_uri(url)
					origin_uri = parse_uri(origin)
					
					return false unless url_uri && origin_uri && url_uri.host && origin_uri.host
					
					scheme_match?(origin_uri.scheme, url_uri.scheme) &&
						url_uri.host.downcase == origin_uri.host.downcase &&
						url_port(url_uri) == url_port(origin_uri)
				end
				
				def url_source_match?(source, url, origin)
					uri = parse_uri(url)
					return false unless uri && uri.scheme
					
					if source == "*"
						# Matches any host with a network scheme:
						return DEFAULT_PORTS.key?(uri.scheme)
					end
					
					if source.end_with?(":")
						# Scheme source, e.g. https: or data::
						return scheme_match?(source.chomp(":"), uri.scheme)
					end
					
					host_source_match?(source, uri, origin)
				end
				
				def host_source_match?(source, uri, origin)
					match = HOST_SOURCE_PATTERN.match(source)
					return false unless match
					
					scheme, wildcard, host, port, _path = match.captures
					return false unless uri.host
					
					# Scheme: if specified, it must match; otherwise the URL scheme must match the origin's scheme, or be a network scheme when no origin is given:
					if scheme
						return false unless scheme_match?(scheme, uri.scheme)
					elsif origin && (origin_uri = parse_uri(origin)) && origin_uri.scheme
						return false unless scheme_match?(origin_uri.scheme, uri.scheme)
					else
						return false unless DEFAULT_PORTS.key?(uri.scheme)
					end
					
					# Host: a wildcard matches the host itself and any of its subdomains:
					if wildcard
						expected = host.downcase
						actual = uri.host.downcase
						
						return false unless actual == expected or actual.end_with?(".#{expected}")
					else
						return false unless uri.host.downcase == host.downcase
					end
					
					# Port: if specified it must match exactly, otherwise the URL must use the default port for its scheme:
					if port
						return false unless url_port(uri) == Integer(port)
					elsif default_port = DEFAULT_PORTS[uri.scheme]
						return false unless url_port(uri) == default_port
					end
					
					return true
				end
				
				# Scheme matching, allowing upgrades, e.g. http: also matches https: URLs:
				def scheme_match?(source_scheme, url_scheme)
					source_scheme == url_scheme ||
						(source_scheme == "http" && url_scheme == "https") ||
						(source_scheme == "ws" && url_scheme == "wss")
				end
				
				def url_port(uri)
					uri.port || DEFAULT_PORTS[uri.scheme]
				end
				
				def parse_uri(value)
					URI.parse(value.to_s)
				rescue URI::InvalidURIError
					nil
				end
			end
			
			# The outcome of evaluating a single policy against a resource load.
			class Verdict
				def initialize(policy:, directive:, matched_source:, allowed:, report_only:)
					@policy = policy
					@directive = directive
					@matched_source = matched_source
					@allowed = allowed
					@report_only = report_only
				end
				
				# The policy that was evaluated.
				attr :policy
				
				# The directive that was actually applied, after following the fallback chain (e.g. default-src when script-src is absent). nil if the policy does not restrict the resource type.
				attr :directive
				
				# The source expression that matched the resource, or nil if none matched.
				attr :matched_source
				
				# Whether this verdict came from a report-only policy. Report-only verdicts never change the overall outcome.
				def report_only?
					@report_only
				end
				
				# Whether the policy allows the resource.
				def allowed?
					@allowed
				end
				
				def blocked?
					!@allowed
				end
			end
			
			# The combined result of evaluating a set of policies. Enforcing policies are combined with intersection semantics: the resource must be allowed by every enforcing policy. Report-only policies are evaluated for visibility but never change the outcome.
			class Result
				def initialize(verdicts)
					@verdicts = verdicts
				end
				
				# One verdict per policy, in evaluation order.
				attr :verdicts
				
				# Verdicts from enforcing policies.
				def enforcing
					@verdicts.reject(&:report_only?)
				end
				
				# Verdicts from report-only policies.
				def report_only
					@verdicts.select(&:report_only?)
				end
				
				# Whether the resource is allowed overall. Report-only verdicts are excluded.
				def allowed?
					enforcing.all?(&:allowed?)
				end
				
				def blocked?
					!allowed?
				end
			end
		end
	end
end
