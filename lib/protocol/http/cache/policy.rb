# frozen_string_literal: true

require "time"

require_relative "../headers"

module Protocol
	module HTTP
		module Cache
			# Makes a freshness decision for one stored response without storing or indexing it.
			class Policy
				USABLE = :usable
				REVALIDATE = :revalidate
				UNSTOREABLE = :unstoreable

				HEURISTICALLY_CACHEABLE_STATUSES = [200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501].freeze

				Calculation = Struct.new(
					:age,
					:freshness_lifetime,
					:stale_time,
					:date_value,
					:age_value,
					:apparent_age,
					:response_delay,
					:corrected_initial_age,
					:resident_time,
					:current_age,
					:request_max_age,
					:max_stale,
					:min_fresh,
					:heuristic_expiration
				)

				Decision = Struct.new(:status, :age, :freshness_lifetime, :calculation, :reasons, keyword_init: true) do
					def usable?
						status == USABLE
					end

					def revalidate?
						status == REVALIDATE
					end

					def unstoreable?
						status == UNSTOREABLE
					end

					def explanation
						[
							"age=#{format_metric(age, "seconds")}",
							"freshness lifetime=#{format_metric(freshness_lifetime, "seconds")}",
							*reasons
						].join("; ")
					end

					def to_h
						{
							status: status,
							age: age,
							freshness_lifetime: freshness_lifetime,
							calculation: calculation.to_h,
							reasons: reasons
						}
					end

					private

					def format_metric(value, unit)
						return "not calculated" if value.nil?
						return "#{format_number(value)} #{unit}" if value.is_a?(Numeric) && value.finite?

						value.inspect
					end

					def format_number(value)
						value == value.to_i ? value.to_i.to_s : value.to_s
					end
				end

				def self.shared(heuristic: nil)
					new(shared: true, heuristic: heuristic)
				end

				def self.private(heuristic: nil)
					new(shared: false, heuristic: heuristic)
				end

				def initialize(shared: false, heuristic: nil)
					@shared = shared
					@heuristic = heuristic || ->(response, date_value, _now) do
						return nil unless HEURISTICALLY_CACHEABLE_STATUSES.include?(response.status)

						last_modified = header_time(response.headers, "last-modified")
						return nil unless date_value && last_modified && last_modified < date_value

						[(date_value - last_modified) / 10, 86_400].min
					end
				end

				def call(request, response, sent_at:, received_at:, now:)
					reasons = []
					request_control = cache_control(request.headers)
					response_control = cache_control(response.headers)

					if response_control&.no_store?
						reasons << "response Cache-Control: no-store forbids storage"
						return decision(UNSTOREABLE, nil, nil, nil, reasons)
					end

					if @shared && response_control&.private?
						reasons << "response Cache-Control: private forbids shared storage"
						return decision(UNSTOREABLE, nil, nil, nil, reasons)
					end

					sent_at = timestamp(sent_at)
					received_at = [timestamp(received_at), sent_at].max
					now = [timestamp(now), received_at].max

					date_value = header_time(response.headers, "date") || received_at
					age_value = header_integer(response.headers, "age") || 0

					apparent_age = [0, received_at - date_value].max
					response_delay = [0, received_at - sent_at].max
					corrected_initial_age = [apparent_age + response_delay, age_value].max
					resident_time = now - received_at
					current_age = corrected_initial_age + resident_time

					request_max_age = request_control&.max_age
					max_stale = request_control&.max_stale
					min_fresh = request_control&.min_fresh || 0

					freshness_lifetime, heuristic_expiration = freshness_lifetime(
						response, response_control, date_value, now, reasons
					)

					calculation = Calculation.new(
						current_age,
						freshness_lifetime,
						freshness_lifetime ? date_value + freshness_lifetime : nil,
						date_value,
						age_value,
						apparent_age,
						response_delay,
						corrected_initial_age,
						resident_time,
						current_age,
						request_max_age,
						max_stale,
						min_fresh,
						heuristic_expiration
					)

					reasons << "age is max(apparent age #{apparent_age} + response delay #{response_delay}, Age #{age_value}) + resident time #{resident_time} = #{current_age}"

					if freshness_lifetime.nil?
						reasons << "no explicit freshness lifetime and heuristic freshness is unavailable"
						return decision(REVALIDATE, current_age, nil, calculation, reasons)
					end

					if forced_revalidation?(request, request_control)
						reasons << "request forces revalidation"
						return decision(REVALIDATE, current_age, freshness_lifetime, calculation, reasons)
					end

					if response_control&.no_cache?
						reasons << "response Cache-Control: no-cache requires revalidation before use"
						return decision(REVALIDATE, current_age, freshness_lifetime, calculation, reasons)
					end

					age_limit = request_max_age || freshness_lifetime

					if current_age + min_fresh <= age_limit
						if request_max_age
							reasons << "request max-age overrides the response freshness lifetime"
						elsif min_fresh.positive?
							reasons << "response is fresh and retains at least #{min_fresh} seconds"
						else
							reasons << "response is fresh"
						end

						return decision(USABLE, current_age, freshness_lifetime, calculation, reasons)
					end

					if request_max_age
						reasons << "request max-age=#{request_max_age} is not satisfied"
						return decision(REVALIDATE, current_age, freshness_lifetime, calculation, reasons)
					end

					stale_for = current_age - freshness_lifetime

					if stale_revalidation_required?(response_control)
						reasons << "response is stale by #{stale_for} seconds and stale use is prohibited"
						return decision(REVALIDATE, current_age, freshness_lifetime, calculation, reasons)
					end

					if max_stale.nil? || stale_for > max_stale
						reasons << "response is stale by #{stale_for} seconds"
						return decision(REVALIDATE, current_age, freshness_lifetime, calculation, reasons)
					end

					reasons << "response is stale by #{stale_for} seconds but request max-stale allows it"
					decision(USABLE, current_age, freshness_lifetime, calculation, reasons)
				end

				private

				def freshness_lifetime(response, response_control, date_value, now, reasons)
					if @shared && (value = response_control&.s_maxage)
						reasons << "shared freshness lifetime uses s-maxage=#{value}"
						return [value, false]
					end

					if value = response_control&.max_age
						reasons << "freshness lifetime uses max-age=#{value}"
						return [value, false]
					end

					expires = header_time(response.headers, "expires")
					if expires
						value = [0, expires - date_value].max
						reasons << "freshness lifetime uses Expires minus Date = #{value}"
						return [value, false]
					end

					value = @heuristic.call(response, date_value, now)
					if value && value.positive?
						reasons << "freshness lifetime #{value} was assigned heuristically"
						return [value, true]
					end

					nil
				end

				def forced_revalidation?(request, request_control)
					request_control&.no_cache? || request.headers["pragma"]&.downcase&.include?("no-cache")
				end

				def stale_revalidation_required?(response_control)
					return true if response_control&.must_revalidate?
					return true if @shared && response_control&.proxy_revalidate?

					false
				end

				def cache_control(headers)
					value = headers["cache-control"]
					return value if value.is_a?(Header::CacheControl)

					Header::CacheControl.coerce(value) if value
				end

				def header_time(headers, name)
					value = headers[name]
					return if value.nil?

					time = value.respond_to?(:to_time) ? value.to_time : ::Time.httpdate(value.to_s)
					time.utc.to_f
				rescue ArgumentError
					nil
				end

				def header_integer(headers, name)
					value = headers[name]
					return if value.nil?

					text = value.to_s.strip
					Integer(text) if text.match?(/\A\d+\z/)
				end

				def timestamp(value)
					raise ArgumentError, "invalid time: #{value.inspect}" unless value.respond_to?(:to_f)

					value.to_f
				end

				def decision(status, age, freshness_lifetime, calculation, reasons)
					Decision.new(
						status: status,
						age: age,
						freshness_lifetime: freshness_lifetime,
						calculation: calculation,
						reasons: reasons
					)
				end
			end
		end
	end
end
