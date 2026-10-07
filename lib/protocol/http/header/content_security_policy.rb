# frozen_string_literal: true

require "uri"

require_relative "multiple"

module Protocol
	module HTTP
		module Header
			# Represents the `content-security-policy` header, which may be specified
			# multiple times. Each header entry is parsed into an independent {Policy}
			# and all enforcing policies are evaluated as an intersection: a resource
			# must be allowed by every policy, rather than by the union (merge) of
			# their source lists.
			#
			# The header can be evaluated offline against a resource type, URL and
			# nonce/hash context, producing a {Result} with a per-policy {Verdict}
			# including the directive that actually took effect.
			class ContentSecurityPolicy < Multiple
				# Fetch directives which fall back to `default-src` when not present.
				FALLBACK = {
					"script-src-elem" => ["script-src", "default-src"],
					"script-src-attr" => ["script-src", "default-src"],
					"style-src-elem" => ["style-src", "default-src"],
					"style-src-attr" => ["style-src", "default-src"],
					"worker-src" => ["child-src", "script-src", "default-src"],
					"child-src" => ["default-src"],
					"frame-src" => ["default-src"],
				}.freeze
				
				# Directives for which `'strict-dynamic'` applies.
				SCRIPT_LOAD_DIRECTIVES = ["script-src", "script-src-elem"].freeze
				
				# Schemes matched by host sources without an explicit scheme, and by `*`.
				NETWORK_SCHEMES = ["http", "https", "ws", "wss"].freeze
				
				# A single parsed content security policy: an ordered map of directive
				# names to source expression lists. Unknown directives are preserved.
				class Policy
					# Parses a raw policy string.
					#
					# @parameter value [String] e.g. `"default-src 'self'; script-src https:".`
					# @returns [Policy] a new instance containing the parsed directives.
					def self.parse(value)
						directives = {}
						
						value.to_s.split(";").each do |part|
							name, *sources = part.split
							
							# Empty entries (e.g. leading/trailing/doubled semicolons):
							next unless name
							
							# The first occurrence of a directive wins:
							directives[name.downcase] ||= sources
						end
						
						self.new(directives)
					end
					
					# Initializes the policy with the given directives.
					#
					# @parameter directives [Hash] a map of directive names to arrays of source expressions.
					def initialize(directives = {})
						@directives = directives
					end
					
					# @attribute [Hash] all parsed directives, including unknown ones.
					attr :directives
					
					# @returns [Array | Nil] the source list for the named directive.
					def [](name)
						@directives[name]
					end
					
					# Finds the directive which actually governs the given resource
					# type, following the fallback chain to `default-src`.
					#
					# @parameter type [String] e.g. `"script"`, `"img"` or a full directive name like `"script-src-elem"`.
					# @returns [Array(String, Array) | Nil] the effective directive name and its source list, or `nil` if no directive applies.
					def effective_directive(type)
						name = self.class.directive_name(type)
						
						[name, *FALLBACK.fetch(name, ["default-src"])].each do |candidate|
							if sources = @directives[candidate]
								return candidate, sources
							end
						end
						
						return nil
					end
					
					# Evaluates this policy against a resource load.
					#
					# @parameter type [String] the resource type, e.g. `"script"`.
					# @parameter url [String | Nil] the resource URL, or `nil` for an inline resource.
					# @parameter nonce [String | Nil] the nonce associated with the element, if any.
					# @parameter hashes [Array(String) | Nil] integrity hashes (e.g. `"sha256-..."`) associated with the element, if any.
					# @parameter origin [String | Nil] the origin (URL) of the protected document, used to resolve `'self'`.
					# @parameter report_only [Boolean] whether this policy is report-only.
					# @returns [Verdict] the outcome, including the effective directive and matched source.
					def evaluate(type, url = nil, nonce: nil, hashes: nil, origin: nil, report_only: false)
						name, sources = effective_directive(type)
						
						unless name
							return Verdict.new(policy: self, directive: nil, source: nil, allowed: true, report_only: report_only)
						end
						
						matched = match_sources(
							sources, url,
							nonce: nonce, hashes: hashes, origin: origin,
							script_load: SCRIPT_LOAD_DIRECTIVES.include?(self.class.directive_name(type)),
						)
						
						Verdict.new(policy: self, directive: name, source: matched, allowed: !matched.nil?, report_only: report_only)
					end
					
					# @returns [Boolean] whether the resource load is allowed by this policy.
					def allows?(...)
						evaluate(...).allowed?
					end
					
					# Serializes the policy back to a raw header value.
					#
					# @returns [String] e.g. `"default-src 'self'; script-src https:".`
					def to_s
						@directives.map{|name, sources| ([name] + sources).join(" ")}.join("; ")
					end
					
					# Resolves a resource type to a directive name.
					#
					# @parameter type [String] e.g. `"script"` or `"script-src-elem"`.
					# @returns [String] the directive name.
					def self.directive_name(type)
						type = type.to_s.downcase
						
						if type.include?("-src")
							type
						else
							"#{type}-src"
						end
					end
					
				private
					
					# Matches a source list against the given context.
					#
					# @returns [String | Nil] the source expression which matched, or `nil` if the load is blocked.
					def match_sources(sources, url, nonce:, hashes:, origin:, script_load:)
						# `'none'` is ignored if other source expressions are present:
						sources = sources.reject{|source| source.casecmp?("'none'")}
						return nil if sources.empty?
						
						# Nonces and hashes take precedence over host-based matching:
						if nonce and matched = sources.find{|source| source == "'nonce-#{nonce}'"}
							return matched
						end
						
						if hashes and matched = sources.find{|source| hashes.any?{|hash| source == "'#{hash}'"}}
							return matched
						end
						
						# When `'strict-dynamic'` is present, host-based source expressions
						# (including `'self'`) are ignored for script loads:
						if script_load and sources.any?{|source| source.casecmp?("'strict-dynamic'")}
							return nil
						end
						
						if url.nil?
							# Inline resource: `'unsafe-inline'` is ignored if the source
							# list contains any nonces or hashes:
							unless sources.any?{|source| source.start_with?("'nonce-", "'sha")}
								if matched = sources.find{|source| source.casecmp?("'unsafe-inline'")}
									return matched
								end
							end
							
							return nil
						end
						
						uri = URI.parse(url.to_s)
						origin_uri = origin && URI.parse(origin.to_s)
						
						sources.find{|source| match_source?(source, uri, origin_uri)}
					end
					
					# @returns [Boolean] whether a single source expression matches the URL.
					def match_source?(source, uri, origin_uri)
						case source.downcase
						when "'self'"
							return !!(origin_uri && same_origin?(uri, origin_uri))
						when /\A'/
							# Other keywords (e.g. `'unsafe-eval'`) and unmatched
							# nonces/hashes never match a URL:
							return false
						when "*"
							return NETWORK_SCHEMES.include?(uri.scheme)
						when /\A([a-z][a-z0-9+.-]*):\z/
							# Scheme source, e.g. `https:`:
							return uri.scheme == $1.downcase
						else
							return match_host_source?(source, uri)
						end
					end
					
					# Matches host sources like `example.com`, `*.example.com`,
					# `https://example.com:8443/path`.
					def match_host_source?(source, uri)
						unless match = /\A(?:(?<scheme>[a-z][a-z0-9+.-]*):\/\/)?(?<host>\*|\*\.[^\/*:]+|[^\/*:]+)(?::(?<port>\*|\d+))?(?<path>\/\S*)?\z/i.match(source)
							return false
						end
						
						if scheme = match[:scheme]
							return false unless uri.scheme == scheme.downcase
						else
							return false unless NETWORK_SCHEMES.include?(uri.scheme)
						end
						
						host = match[:host].downcase
						
						if host == "*"
							# Any host matches.
						elsif host.start_with?("*.")
							suffix = host[1..]
							return false unless uri.host&.downcase&.end_with?(suffix)
						else
							return false unless uri.host&.downcase == host
						end
						
						if port = match[:port]
							return false unless port == "*" || uri.port == Integer(port)
						else
							return false unless uri.port == default_port(uri.scheme)
						end
						
						if path = match[:path]
							if path.end_with?("/")
								return false unless uri.path.start_with?(path)
							else
								return false unless uri.path == path
							end
						end
						
						return true
					end
					
					def same_origin?(uri, origin_uri)
						uri.scheme == origin_uri.scheme &&
							uri.host&.downcase == origin_uri.host&.downcase &&
							uri.port == origin_uri.port
					end
					
					def default_port(scheme)
						{"http" => 80, "https" => 443, "ws" => 80, "wss" => 443}[scheme]
					end
				end
				
				# The outcome of evaluating a single policy against a resource load.
				class Verdict
					def initialize(policy:, directive:, source:, allowed:, report_only: false)
						@policy = policy
						@directive = directive
						@source = source
						@allowed = allowed
						@report_only = report_only
					end
					
					# @attribute [Policy] the policy which was evaluated.
					attr :policy
					
					# @attribute [String | Nil] the directive which actually took effect (after `default-src` fallback), or `nil` if no directive applied.
					attr :directive
					
					# @attribute [String | Nil] the source expression which matched, or `nil` if the load was blocked.
					attr :source
					
					# @returns [Boolean] whether this policy allows the load.
					def allowed?
						@allowed
					end
					
					# @returns [Boolean] whether this verdict came from a report-only policy.
					def report_only?
						@report_only
					end
					
					# @returns [Boolean] whether this verdict came from an enforcing policy.
					def enforcing?
						!@report_only
					end
					
					def to_s
						state = allowed? ? "allow" : "block"
						source = @source ? " matched #{@source.inspect}" : ""
						"#{state} (#{@directive || "no directive"}#{source})"
					end
					
					alias inspect to_s
				end
				
				# The aggregated outcome of evaluating several policies. Enforcing
				# policies are intersected; report-only policies are evaluated for
				# visibility but never change the overall result.
				class Result
					include Enumerable
					
					def initialize(verdicts)
						@verdicts = verdicts
					end
					
					# @attribute [Array(Verdict)] one verdict per evaluated policy.
					attr :verdicts
					
					def each(&block)
						@verdicts.each(&block)
					end
					
					# @returns [Array(Verdict)] verdicts from enforcing policies.
					def enforcing
						@verdicts.select(&:enforcing?)
					end
					
					# @returns [Array(Verdict)] verdicts from report-only policies.
					def report_only
						@verdicts.select(&:report_only?)
					end
					
					# @returns [Boolean] whether the load is allowed by every enforcing policy.
					def allowed?
						enforcing.all?(&:allowed?)
					end
				end
				
				# Parses a raw header value into a single-policy header.
				#
				# @parameter value [String] a raw header value containing one policy.
				# @returns [ContentSecurityPolicy] a new instance containing the parsed policy.
				def self.parse(value)
					self.new([Policy.parse(value)])
				end
				
				# Coerces a value into a parsed header object.
				#
				# @parameter value [String | Policy | Array] the value to coerce.
				# @returns [ContentSecurityPolicy] a parsed header object.
				def self.coerce(value)
					case value
					when Array
						self.new(value.map{|item| item.is_a?(Policy) ? item : Policy.parse(item.to_s)})
					when Policy
						self.new([value])
					else
						self.parse(value.to_s)
					end
				end
				
				# Adds a policy to the header.
				#
				# @parameter value [String | Policy] a raw policy string or parsed policy.
				def <<(value)
					super(value.is_a?(Policy) ? value : Policy.parse(value.to_s))
				end
				
				# @returns [Boolean] whether these policies are report-only.
				def report_only?
					false
				end
				
				# Evaluates all policies against a resource load. Enforcing policies
				# are intersected: the load must be allowed by every one of them.
				#
				# @parameter type [String] the resource type, e.g. `"script"`.
				# @parameter url [String | Nil] the resource URL, or `nil` for an inline resource.
				# @parameter report_only [ContentSecurityPolicy | Nil] optional report-only policies to evaluate alongside (never affect the result).
				# @parameter context [Hash] nonce/hash/origin context, see {Policy#evaluate}.
				# @returns [Result] the aggregated outcome with one verdict per policy.
				def evaluate(type, url = nil, report_only: nil, **context)
					verdicts = map{|policy| policy.evaluate(type, url, report_only: report_only?, **context)}
					
					if report_only
						verdicts.concat(report_only.map{|policy| policy.evaluate(type, url, report_only: true, **context)})
					end
					
					Result.new(verdicts)
				end
				
				# @returns [Boolean] whether the resource load is allowed by every enforcing policy.
				def allows?(...)
					evaluate(...).allowed?
				end
				
				# Represents the `content-security-policy-report-only` header. Evaluated
				# exactly like an enforcing policy, but verdicts are marked report-only
				# and never change the overall allowed result.
				class ReportOnly < ContentSecurityPolicy
					# @returns [Boolean] whether these policies are report-only.
					def report_only?
						true
					end
				end
			end
		end
	end
end
