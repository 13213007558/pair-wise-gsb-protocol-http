# frozen_string_literal: true

require "time"

require_relative "header/cache_control"

module Protocol
	module HTTP
		# A standalone HTTP cache decision maker, following RFC 9111. It does not store
		# responses or index them by `vary` — given a request, a stored response and the
		# relevant timestamps, it decides whether the stored response can be used
		# directly, must be revalidated, or must not be stored at all.
		module Cache
			# The outcome of evaluating a stored response against a request.
			class Decision
				# The stored response may be used directly to satisfy the request.
				USE = :use
				
				# The stored response must be revalidated with the origin server before it can be used.
				REVALIDATE = :revalidate
				
				# The response must not be stored by this cache.
				NOT_STORABLE = :not_storable
				
				# @parameter action [Symbol] one of {USE}, {REVALIDATE} or {NOT_STORABLE}.
				# @parameter age [Numeric | Nil] the computed current age of the stored response, in seconds.
				# @parameter freshness_lifetime [Numeric | Nil] the computed freshness lifetime of the stored response, in seconds.
				# @parameter explanation [Array(String)] a step-by-step explanation of how the age and freshness lifetime were computed, and why the action was chosen.
				def initialize(action, age: nil, freshness_lifetime: nil, explanation: [])
					@action = action
					@age = age
					@freshness_lifetime = freshness_lifetime
					@explanation = explanation
				end
				
				# @attribute [Symbol] the recommended action: `:use`, `:revalidate` or `:not_storable`.
				attr :action
				
				# @attribute [Numeric | Nil] the current age of the stored response in seconds.
				attr :age
				
				# @attribute [Numeric | Nil] the freshness lifetime of the stored response in seconds.
				attr :freshness_lifetime
				
				# @attribute [Array(String)] a human-readable explanation of the computation.
				attr :explanation
				
				# @returns [Boolean] whether the stored response may be used directly.
				def use?
					@action == USE
				end
				
				# @returns [Boolean] whether the stored response must be revalidated before use.
				def revalidate?
					@action == REVALIDATE
				end
				
				# @returns [Boolean] whether the response must not be stored.
				def not_storable?
					@action == NOT_STORABLE
				end
				
				# @returns [Boolean] whether the response may be stored.
				def storable?
					!not_storable?
				end
				
				# @returns [Boolean] whether the stored response is still within its freshness lifetime.
				def fresh?
					if @age and @freshness_lifetime
						@age <= @freshness_lifetime
					else
						false
					end
				end
			end
			
			# Evaluates stored responses against incoming requests. Create a shared
			# (proxy/CDN) policy with {Policy.shared} or a private (browser/client)
			# policy with {Policy.private} — the two apply different rules for
			# `s-maxage`, `private`, `proxy-revalidate` and `authorization`.
			class Policy
				# The default fraction of the time since last modification used for heuristic freshness.
				DEFAULT_HEURISTIC_FRACTION = 0.1
				
				# Create a policy suitable for a shared cache (e.g. a proxy or CDN).
				def self.shared(**options)
					self.new(shared: true, **options)
				end
				
				# Create a policy suitable for a private cache (e.g. a browser cache).
				def self.private(**options)
					self.new(shared: false, **options)
				end
				
				# @parameter shared [Boolean] whether this policy applies shared-cache semantics.
				# @parameter heuristic_fraction [Numeric] the fraction of the time since last modification used when computing heuristic freshness.
				def initialize(shared: false, heuristic_fraction: DEFAULT_HEURISTIC_FRACTION)
					@shared = shared
					@heuristic_fraction = heuristic_fraction
				end
				
				# @attribute [Numeric] the fraction used for heuristic freshness calculations.
				attr :heuristic_fraction
				
				# @returns [Boolean] whether this is a shared cache policy.
				def shared?
					@shared
				end
				
				# Evaluate a stored response against an incoming request.
				#
				# @parameter request [Request] the incoming request.
				# @parameter response [Response] the stored response.
				# @parameter sent_at [Time | Numeric] the time the request that produced the stored response was sent.
				# @parameter received_at [Time | Numeric] the time the stored response was received.
				# @parameter now [Time | Numeric] the current time.
				# @returns [Decision] the decision, including the computed age, freshness lifetime and an explanation.
				def evaluate(request, response, sent_at:, received_at:, now: ::Time.now)
					sent_at = sent_at.to_f
					received_at = received_at.to_f
					now = now.to_f
					
					explanation = []
					
					request_cache_control = cache_control_for(request)
					response_cache_control = cache_control_for(response)
					
					unless storable?(request, request_cache_control, response_cache_control, explanation)
						return Decision.new(Decision::NOT_STORABLE, explanation: explanation)
					end
					
					age = compute_age(response, sent_at, received_at, now, explanation)
					freshness_lifetime = compute_freshness_lifetime(response, response_cache_control, explanation)
					
					action = decide(request, request_cache_control, response_cache_control, age, freshness_lifetime, explanation)
					
					return Decision.new(action, age: age, freshness_lifetime: freshness_lifetime, explanation: explanation)
				end
				
				private
				
				# Whether the response may be stored by this cache at all.
				def storable?(request, request_cache_control, response_cache_control, explanation)
					if request_cache_control&.no_store?
						explanation << "request contains `no-store`: the response must not be stored."
						return false
					end
					
					if response_cache_control&.no_store?
						explanation << "response contains `no-store`: it must not be stored."
						return false
					end
					
					if @shared
						if response_cache_control&.private?
							explanation << "shared cache: response contains `private`, so it must not be stored."
							return false
						end
						
						if request.headers.include?("authorization")
							unless response_cache_control&.public? or response_cache_control&.s_maxage or response_cache_control&.must_revalidate?
								explanation << "shared cache: request contains `authorization` and the response does not explicitly allow shared caching (`public`, `s-maxage` or `must-revalidate`)."
								return false
							end
						end
					end
					
					return true
				end
				
				# Compute the current age of the stored response, following RFC 9111 §4.2.3.
				def compute_age(response, sent_at, received_at, now, explanation)
					date_value = http_time(response.headers["date"])
					age_value = integer_value(response.headers["age"]) || 0
					
					if date_value
						# A date in the future (clock skew) is clamped to zero:
						apparent_age = [0, received_at - date_value].max
						explanation << "age: apparent_age = max(0, received_at - date) = max(0, #{format_seconds(received_at - date_value)}) = #{format_seconds(apparent_age)}s."
					else
						# A response without a valid date is assumed to be generated when received:
						apparent_age = 0
						explanation << "age: no valid `date` header, assuming the response was generated when it was received (apparent_age = 0s)."
					end
					
					response_delay = received_at - sent_at
					corrected_age_value = age_value + response_delay
					explanation << "age: corrected_age_value = age_header (#{format_seconds(age_value)}s) + response_delay (#{format_seconds(response_delay)}s) = #{format_seconds(corrected_age_value)}s."
					
					corrected_initial_age = [apparent_age, corrected_age_value].max
					explanation << "age: corrected_initial_age = max(apparent_age, corrected_age_value) = #{format_seconds(corrected_initial_age)}s."
					
					resident_time = now - received_at
					current_age = corrected_initial_age + resident_time
					explanation << "age: current_age = corrected_initial_age (#{format_seconds(corrected_initial_age)}s) + resident_time (#{format_seconds(resident_time)}s) = #{format_seconds(current_age)}s."
					
					return current_age
				end
				
				# Compute the freshness lifetime of the stored response, following RFC 9111 §4.2.2.
				def compute_freshness_lifetime(response, cache_control, explanation)
					if @shared and seconds = cache_control&.s_maxage
						explanation << "freshness_lifetime: shared cache, `s-maxage=#{seconds}` takes precedence = #{seconds}s."
						return seconds
					end
					
					if seconds = cache_control&.max_age
						explanation << "freshness_lifetime: `max-age=#{seconds}` = #{seconds}s."
						return seconds
					end
					
					date_value = http_time(response.headers["date"])
					
					if expires_value = http_time(response.headers["expires"])
						if date_value
							lifetime = [expires_value - date_value, 0].max
							explanation << "freshness_lifetime: expires - date = #{format_seconds(expires_value - date_value)}s, clamped to #{format_seconds(lifetime)}s."
							return lifetime
						end
					end
					
					if date_value and last_modified = http_time(response.headers["last-modified"])
						if date_value > last_modified
							lifetime = (date_value - last_modified) * @heuristic_fraction
							explanation << "freshness_lifetime: heuristic = #{format_seconds(@heuristic_fraction)} * (date - last-modified) = #{format_seconds(@heuristic_fraction)} * #{format_seconds(date_value - last_modified)} = #{format_seconds(lifetime)}s."
							return lifetime
						end
					end
					
					explanation << "freshness_lifetime: no explicit or heuristic freshness information, assuming 0s (immediately stale)."
					return 0
				end
				
				# Decide what to do with a stored response of the given age and freshness lifetime.
				def decide(request, request_cache_control, response_cache_control, age, freshness_lifetime, explanation)
					if request_cache_control&.no_cache? or pragma_no_cache?(request)
						explanation << "request contains `no-cache`: revalidation is required."
						return Decision::REVALIDATE
					end
					
					if response_cache_control&.no_cache?
						explanation << "response contains `no-cache`: revalidation is required before use."
						return Decision::REVALIDATE
					end
					
					if request_cache_control and maximum_age = request_cache_control.max_age
						if age > maximum_age
							explanation << "request `max-age=#{maximum_age}`: current age (#{format_seconds(age)}s) exceeds it, revalidation is required."
							return Decision::REVALIDATE
						end
					end
					
					if request_cache_control and minimum_fresh = request_cache_control.min_fresh
						remaining = freshness_lifetime - age
						
						if remaining < minimum_fresh
							explanation << "request `min-fresh=#{minimum_fresh}`: only #{format_seconds(remaining)}s of freshness remains, revalidation is required."
							return Decision::REVALIDATE
						end
					end
					
					if age <= freshness_lifetime
						explanation << "current age (#{format_seconds(age)}s) is within the freshness lifetime (#{format_seconds(freshness_lifetime)}s): the stored response can be used directly."
						return Decision::USE
					end
					
					staleness = age - freshness_lifetime
					
					if must_revalidate?(response_cache_control)
						explanation << "response is stale by #{format_seconds(staleness)}s and must be revalidated once stale (`must-revalidate`/`proxy-revalidate`): revalidation is required."
						return Decision::REVALIDATE
					end
					
					if request_cache_control and max_stale = request_cache_control.max_stale
						if max_stale == true
							explanation << "request `max-stale`: a stale response (#{format_seconds(staleness)}s stale) is acceptable."
							return Decision::USE
						elsif staleness <= max_stale
							explanation << "request `max-stale=#{max_stale}`: staleness (#{format_seconds(staleness)}s) is within the allowed limit."
							return Decision::USE
						else
							explanation << "request `max-stale=#{max_stale}`: staleness (#{format_seconds(staleness)}s) exceeds the allowed limit, revalidation is required."
							return Decision::REVALIDATE
						end
					end
					
					explanation << "current age (#{format_seconds(age)}s) exceeds the freshness lifetime (#{format_seconds(freshness_lifetime)}s): revalidation is required."
					return Decision::REVALIDATE
				end
				
				# Whether the stored response must be revalidated once it becomes stale.
				def must_revalidate?(cache_control)
					return false unless cache_control
					
					if cache_control.must_revalidate?
						return true
					end
					
					# For shared caches, `proxy-revalidate` applies, and `s-maxage` implies it:
					if @shared and (cache_control.proxy_revalidate? or cache_control.s_maxage)
						return true
					end
					
					return false
				end
				
				def pragma_no_cache?(request)
					if pragma = request.headers["pragma"]
						pragma.to_s.downcase.include?("no-cache")
					end
				end
				
				def cache_control_for(message)
					if value = message.headers["cache-control"]
						Header::CacheControl.coerce(value)
					end
				end
				
				def http_time(value)
					if value
						::Time.httpdate(value.to_s).to_f
					end
				rescue ArgumentError
					nil
				end
				
				def integer_value(value)
					if value and value.to_s =~ /\A[0-9]+\z/
						Integer(value.to_s)
					end
				end
				
				# Format a number of seconds for inclusion in the explanation, avoiding
				# noisy floating point representations for whole numbers.
				def format_seconds(value)
					if value.truncate == value
						value.truncate
					else
						value.round(2)
					end
				end
			end
		end
	end
end
