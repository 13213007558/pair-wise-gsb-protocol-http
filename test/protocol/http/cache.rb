# frozen_string_literal: true

require "protocol/http/cache"
require "protocol/http/request"
require "protocol/http/response"

describe Protocol::HTTP::Cache::Policy do
	# A fixed clock: the request was sent at T+0, the response was received at
	# T+1, and "now" is T+100. With a `date` header of T+0 and no `age` header,
	# the current age of a stored response is exactly 100 seconds.
	let(:sent_at) {::Time.utc(2026, 1, 1, 12, 0, 0)}
	let(:received_at) {sent_at + 1}
	let(:now) {received_at + 99}
	
	def http_date(time)
		time.utc.httpdate
	end
	
	def request_with(headers = {})
		Protocol::HTTP::Request["GET", "/", headers]
	end
	
	def response_with(headers = {})
		Protocol::HTTP::Response[200, headers]
	end
	
	let(:request) {request_with}
	let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "max-age=200")}
	
	let(:policy) {subject.shared}
	let(:decision) {policy.evaluate(request, response, sent_at: sent_at, received_at: received_at, now: now)}
	
	with "a fresh stored response" do
		it "can be used directly and explains the computation" do
			expect(decision).to be(:use?)
			expect(decision).not.to be(:revalidate?)
			expect(decision).to be(:storable?)
			expect(decision).to be(:fresh?)
			
			# corrected_initial_age = max(1, 0 + 1) = 1, resident_time = 99:
			expect(decision.age).to be == 100
			expect(decision.freshness_lifetime).to be == 200
			
			expect(decision.explanation.join("\n")).to be(:include?, "current_age")
			expect(decision.explanation.join("\n")).to be(:include?, "freshness_lifetime")
		end
	end
	
	with "a skewed date header" do
		# The origin clock is 60 seconds behind: the response claims to be
		# generated before the request was even sent.
		let(:response) {response_with("date" => http_date(sent_at - 60), "cache-control" => "max-age=200")}
		
		it "accounts for the skew using apparent_age" do
			# apparent_age = max(0, received_at - date) = 61, which dominates the
			# corrected age value of 1; resident_time = 99:
			expect(decision.age).to be == 160
			expect(decision).to be(:use?)
		end
	end
	
	with "a date header in the future" do
		let(:response) {response_with("date" => http_date(received_at + 60), "cache-control" => "max-age=200")}
		
		it "clamps apparent_age to zero" do
			# apparent_age = max(0, -60) = 0, corrected_age_value = 1, resident_time = 99:
			expect(decision.age).to be == 100
			expect(decision).to be(:use?)
		end
	end
	
	with "a large age header" do
		let(:response) {response_with("date" => http_date(sent_at), "age" => "500", "cache-control" => "max-age=60")}
		
		it "requires revalidation" do
			# corrected_age_value = 500 + 1 = 501, resident_time = 99:
			expect(decision.age).to be == 600
			expect(decision.freshness_lifetime).to be == 60
			expect(decision).to be(:revalidate?)
			expect(decision).not.to be(:fresh?)
		end
	end
	
	with "a request that forces revalidation" do
		with "cache-control: no-cache" do
			let(:request) {request_with("cache-control" => "no-cache")}
			
			it "requires revalidation even though the response is fresh" do
				expect(decision).to be(:revalidate?)
			end
		end
		
		with "pragma: no-cache" do
			let(:request) {request_with("pragma" => "no-cache")}
			
			it "requires revalidation" do
				expect(decision).to be(:revalidate?)
			end
		end
		
		with "cache-control: max-age=0" do
			let(:request) {request_with("cache-control" => "max-age=0")}
			
			it "requires revalidation" do
				expect(decision).to be(:revalidate?)
			end
		end
	end
	
	with "s-maxage" do
		let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "max-age=10, s-maxage=1000")}
		
		with "a shared cache" do
			let(:policy) {subject.shared}
			
			it "prefers s-maxage over max-age" do
				expect(decision.freshness_lifetime).to be == 1000
				expect(decision).to be(:use?)
			end
		end
		
		with "a private cache" do
			let(:policy) {subject.private}
			
			it "ignores s-maxage and uses max-age" do
				expect(decision.freshness_lifetime).to be == 10
				expect(decision).to be(:revalidate?)
			end
		end
	end
	
	with "max-stale" do
		let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "max-age=10")}
		
		with "a value that covers the staleness" do
			let(:request) {request_with("cache-control" => "max-stale=120")}
			
			it "allows the stale response to be used" do
				# Stale by 90 seconds, which is within the allowed 120:
				expect(decision).to be(:use?)
				expect(decision).not.to be(:fresh?)
			end
		end
		
		with "a value that does not cover the staleness" do
			let(:request) {request_with("cache-control" => "max-stale=30")}
			
			it "requires revalidation" do
				expect(decision).to be(:revalidate?)
			end
		end
		
		with "no value" do
			let(:request) {request_with("cache-control" => "max-stale")}
			
			it "allows any staleness" do
				expect(decision).to be(:use?)
			end
		end
		
		with "must-revalidate" do
			let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "max-age=10, must-revalidate")}
			let(:request) {request_with("cache-control" => "max-stale=1000")}
			
			it "requires revalidation once stale" do
				expect(decision).to be(:revalidate?)
			end
		end
		
		with "proxy-revalidate" do
			let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "max-age=10, proxy-revalidate")}
			let(:request) {request_with("cache-control" => "max-stale=1000")}
			
			with "a shared cache" do
				let(:policy) {subject.shared}
				
				it "requires revalidation once stale" do
					expect(decision).to be(:revalidate?)
				end
			end
			
			with "a private cache" do
				let(:policy) {subject.private}
				
				it "does not apply and allows max-stale" do
					expect(decision).to be(:use?)
				end
			end
		end
	end
	
	with "min-fresh" do
		let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "max-age=120")}
		
		with "more remaining freshness than requested" do
			let(:request) {request_with("cache-control" => "min-fresh=10")}
			
			it "can be used directly" do
				# 20 seconds of freshness remain, which is more than 10:
				expect(decision).to be(:use?)
			end
		end
		
		with "less remaining freshness than requested" do
			let(:request) {request_with("cache-control" => "min-fresh=30")}
			
			it "requires revalidation" do
				expect(decision).to be(:revalidate?)
			end
		end
	end
	
	with "heuristic freshness" do
		# Last modified 1000 seconds before the date header, so the heuristic
		# freshness lifetime is 10% of that: 100 seconds.
		let(:response) {response_with("date" => http_date(sent_at), "last-modified" => http_date(sent_at - 1000))}
		
		it "computes a heuristic freshness lifetime" do
			expect(decision.freshness_lifetime).to be_within(0.001).of(100)
			expect(decision).to be(:use?)
		end
		
		with "an older response" do
			let(:now) {received_at + 149}
			
			it "requires revalidation once the heuristic lifetime is exceeded" do
				expect(decision.age).to be == 150
				expect(decision).to be(:revalidate?)
			end
		end
	end
	
	with "no-store" do
		with "in the response" do
			let(:response) {response_with("cache-control" => "no-store")}
			
			it "is not storable" do
				expect(decision).to be(:not_storable?)
				expect(decision).not.to be(:storable?)
			end
		end
		
		with "in the request" do
			let(:request) {request_with("cache-control" => "no-store")}
			
			it "is not storable" do
				expect(decision).to be(:not_storable?)
			end
		end
	end
	
	with "a private response" do
		let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "private, max-age=200")}
		
		with "a shared cache" do
			let(:policy) {subject.shared}
			
			it "is not storable" do
				expect(decision).to be(:not_storable?)
			end
		end
		
		with "a private cache" do
			let(:policy) {subject.private}
			
			it "can be stored and used" do
				expect(decision).to be(:use?)
			end
		end
	end
	
	with "an authorized request" do
		let(:request) {request_with("authorization" => "Bearer token")}
		
		with "a shared cache" do
			let(:policy) {subject.shared}
			
			it "is not storable without explicit permission" do
				expect(decision).to be(:not_storable?)
			end
			
			with "a public response" do
				let(:response) {response_with("date" => http_date(sent_at), "cache-control" => "public, max-age=200")}
				
				it "can be stored and used" do
					expect(decision).to be(:use?)
				end
			end
		end
		
		with "a private cache" do
			let(:policy) {subject.private}
			
			it "can be stored and used" do
				expect(decision).to be(:use?)
			end
		end
	end
end
