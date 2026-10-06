# frozen_string_literal: true

require "protocol/http"

describe Protocol::HTTP::Cache::Policy do
	let(:request) {Protocol::HTTP::Request["GET", "/", request_headers]}
	let(:request_headers) {Hash.new}
	let(:response) {Protocol::HTTP::Response[200, response_headers]}
	let(:response_headers) do
		{
			"date" => Time.at(1000).utc.httpdate,
			"cache-control" => "max-age=60"
		}
	end
	let(:sent_at) {1000}
	let(:received_at) {1000}
	let(:now) {1050}

	def decision(shared: false)
		policy = shared ? subject.shared : subject.private
		policy.call(request, response, sent_at: sent_at, received_at: received_at, now: now)
	end

	it "is usable and reports age and freshness lifetime" do
		result = decision

		expect(result).to be(:usable?)
		expect(result.status).to be == :usable
		expect(result.age).to be == 50
		expect(result.freshness_lifetime).to be == 60
		expect(result.calculation.stale_time).to be == 1060
		expect(result.explanation).to be =~ /age=50 seconds/
		expect(result.explanation).to be =~ /freshness lifetime=60 seconds/
	end

	with "a clock-skewed Date" do
		let(:received_at) {1005}
		let(:response_headers) do
			{
				"date" => Time.at(1010).utc.httpdate,
				"cache-control" => "max-age=60"
			}
		end

		it "does not use a negative apparent age" do
			result = decision

			expect(result).to be(:usable?)
			expect(result.calculation.apparent_age).to be == 0
			expect(result.calculation.corrected_initial_age).to be == 5
			expect(result.calculation.age_value).to be == 0
			expect(result.calculation.resident_time).to be == 45
			expect(result.age).to be == 50
		end
	end

	with "a large Age header" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"age" => "120",
				"cache-control" => "max-age=60"
			}
		end

		it "uses the supplied Age and requires revalidation" do
			result = decision

			expect(result).to be(:revalidate?)
			expect(result.age).to be == 170
			expect(result.freshness_lifetime).to be == 60
			expect(result.reasons.any? {|reason| reason =~ /is stale/}).to be == true
		end
	end

	with "a forced revalidation request" do
		let(:request_headers) {{"cache-control" => "no-cache"}}

		it "requires revalidation even while fresh" do
			result = decision

			expect(result).to be(:revalidate?)
			expect(result.age).to be == 50
			expect(result.freshness_lifetime).to be == 60
			expect(result.reasons.any? {|reason| reason =~ /request forces revalidation/}).to be == true
		end
	end

	with "s-maxage" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"cache-control" => "max-age=60, s-maxage=30"
			}
		end
		let(:now) {1040}

		it "uses s-maxage for shared caches" do
			result = decision(shared: true)

			expect(result).to be(:revalidate?)
			expect(result.freshness_lifetime).to be == 30
			expect(result.reasons.any? {|reason| reason =~ /shared freshness lifetime uses s-maxage/}).to be == true
	end

	it "uses max-age for private caches" do
		result = decision

		expect(result).to be(:usable?)
		expect(result.freshness_lifetime).to be == 60
		end
	end

	with "proxy-revalidate" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"cache-control" => "max-age=60, proxy-revalidate"
			}
		end
		let(:request_headers) {{"cache-control" => "max-stale"}}
		let(:now) {1100}

		it "prohibits stale responses only for shared caches" do
			expect(decision(shared: true)).to be(:revalidate?)
			expect(decision).to be(:usable?)
		end
	end

	with "must-revalidate" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"cache-control" => "max-age=60, must-revalidate"
			}
		end
		let(:request_headers) {{"cache-control" => "max-stale"}}
		let(:now) {1100}

		it "prohibits stale responses for private caches too" do
			result = decision

			expect(result).to be(:revalidate?)
			expect(result.reasons.any? {|reason| reason =~ /stale use is prohibited/}).to be == true
		end
	end

	with "max-stale" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"cache-control" => "max-age=60"
			}
		end

		with "an allowed stale window" do
			let(:request_headers) {{"cache-control" => "max-stale=20"}}
			let(:now) {1075}

			it "can use a stale response" do
				result = decision

				expect(result).to be(:usable?)
				expect(result.age).to be == 75
				expect(result.calculation.max_stale).to be == 20
				expect(result.reasons.any? {|reason| reason =~ /max-stale allows/}).to be == true
			end
		end

		with "an exceeded stale window" do
			let(:request_headers) {{"cache-control" => "max-stale=10"}}
			let(:now) {1075}

			it "requires revalidation" do
				result = decision

				expect(result).to be(:revalidate?)
				expect(result.calculation.max_stale).to be == 10
			end
		end
	end

	with "min-fresh" do
		let(:request_headers) {{"cache-control" => "min-fresh=20"}}
		let(:now) {1050}

		it "requires remaining freshness to satisfy the request" do
			result = decision

			expect(result).to be(:revalidate?)
			expect(result.calculation.min_fresh).to be == 20
			expect(result.reasons.any? {|reason| reason =~ /stale by -10/}).to be == true
		end
	end

	with "request max-age" do
		let(:request_headers) {{"cache-control" => "max-age=20"}}

		it "uses the request age limit while retaining the response lifetime" do
			result = decision

			expect(result).to be(:revalidate?)
			expect(result.age).to be == 50
			expect(result.freshness_lifetime).to be == 60
			expect(result.calculation.request_max_age).to be == 20
			expect(result.reasons.any? {|reason| reason =~ /request max-age=20/}).to be == true
		end
	end

	with "heuristic freshness" do
		let(:response_headers) do
			{
				"date" => Time.at(2000).utc.httpdate,
				"last-modified" => Time.at(1000).utc.httpdate
			}
		end
		let(:sent_at) {2000}
		let(:received_at) {2000}
		let(:now) {2050}

		it "uses one tenth of Last-Modified age up to the cap" do
			result = decision

			expect(result).to be(:usable?)
			expect(result.freshness_lifetime).to be == 100
			expect(result.calculation.heuristic_expiration).to be == true
			expect(result.reasons.any? {|reason| reason =~ /heuristically/}).to be == true
		end
	end

	with "heuristic freshness is unavailable" do
		let(:response) {Protocol::HTTP::Response[500, response_headers]}
		let(:response_headers) do
			{
				"date" => Time.at(2000).utc.httpdate,
				"last-modified" => Time.at(1000).utc.httpdate
			}
		end
		let(:sent_at) {2000}
		let(:received_at) {2000}
		let(:now) {2050}

		it "requires revalidation" do
			result = decision

			expect(result).to be(:revalidate?)
			expect(result.freshness_lifetime).to be == nil
		end
	end

	with "no-store" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"cache-control" => "no-store, max-age=60"
			}
		end

		it "is unstoreable" do
			result = decision

			expect(result).to be(:unstoreable?)
			expect(result.age).to be == nil
			expect(result.freshness_lifetime).to be == nil
		end
	end

	with "private" do
		let(:response_headers) do
			{
				"date" => Time.at(1000).utc.httpdate,
				"cache-control" => "private, max-age=60"
			}
		end

		it "is unstoreable in a shared cache but usable in a private cache" do
			expect(decision(shared: true)).to be(:unstoreable?)
			expect(decision).to be(:usable?)
		end
	end
end
