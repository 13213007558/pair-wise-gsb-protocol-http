# frozen_string_literal: true

require_relative "multiple"
require_relative "../content_security_policy"

module Protocol
	module HTTP
		module Header
			# Represents one or more content-security-policy headers.
			#
			# Each header entry is a distinct policy; policies are never merged. A resource must be allowed by every enforcing policy (intersection semantics), so the policies are kept separate and evaluated individually.
			class ContentSecurityPolicy < Multiple
				# Parses a raw header value.
				#
				# @parameter value [String] a single serialized policy.
				# @returns [ContentSecurityPolicy] a new instance containing the parsed policy.
				def self.parse(value)
					self.new([HTTP::ContentSecurityPolicy::Policy.parse(value)])
				end
				
				# Coerces a value into a parsed header object.
				#
				# @parameter value [String | Array] the value to coerce.
				# @returns [ContentSecurityPolicy] a parsed header object.
				def self.coerce(value)
					case value
					when Array
						self.new(value.map{|policy| coerce_policy(policy)})
					else
						self.parse(value.to_s)
					end
				end
				
				# Adds a policy to the header.
				#
				# @parameter value [String | HTTP::ContentSecurityPolicy::Policy] a serialized policy or a parsed policy.
				def <<(value)
					super(self.class.coerce_policy(value))
				end
				
				# Converts the parsed policies back into a raw header value.
				#
				# @returns [String] a newline-separated string of serialized policies.
				def to_s
					map(&:to_s).join("\n")
				end
				
				# Whether these policies are report-only. Report-only policies never change whether a resource is allowed.
				#
				# @returns [Boolean]
				def report_only?
					false
				end
				
				# Evaluate a resource load against all policies in this header.
				#
				# @parameter resource_type [Symbol] e.g. :script, :style, :img, ...
				# @parameter url [String | Nil] the URL of the resource, or nil for inline resources.
				# @parameter context [Hash] nonce, hashes, origin and inline context, see HTTP::ContentSecurityPolicy.evaluate.
				# @returns [HTTP::ContentSecurityPolicy::Result] the combined result, with one verdict per policy.
				def evaluate(resource_type, url = nil, **context)
					verdicts = map{|policy| policy.evaluate(resource_type, url, report_only: report_only?, **context)}
					
					HTTP::ContentSecurityPolicy::Result.new(verdicts)
				end
				
				# Evaluate a resource load against a set of CSP headers, e.g. one enforcing and one report-only header.
				#
				# @parameter headers [Array(ContentSecurityPolicy)] the headers to evaluate; report-only headers never affect the outcome.
				# @returns [HTTP::ContentSecurityPolicy::Result] the combined result, with one verdict per policy.
				def self.evaluate(headers, resource_type, url = nil, **context)
					verdicts = headers.flat_map do |header|
						header.map{|policy| policy.evaluate(resource_type, url, report_only: header.report_only?, **context)}
					end
					
					HTTP::ContentSecurityPolicy::Result.new(verdicts)
				end
				
				# Whether this header is acceptable in HTTP trailers.
				# @returns [Boolean] false, as content security policies apply to the response as a whole.
				def self.trailer?
					false
				end
				
				private
				
				def self.coerce_policy(value)
					case value
					when HTTP::ContentSecurityPolicy::Policy
						value
					else
						HTTP::ContentSecurityPolicy::Policy.parse(value.to_s)
					end
				end
			end
			
			# Represents one or more content-security-policy-report-only headers. Parsed identically to ContentSecurityPolicy, but evaluation never changes whether a resource is allowed.
			class ContentSecurityPolicyReportOnly < ContentSecurityPolicy
				# @returns [Boolean] true, as report-only policies never change whether a resource is allowed.
				def report_only?
					true
				end
			end
		end
	end
end
