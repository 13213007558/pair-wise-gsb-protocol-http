# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Protocol
	module HTTP
		module Header
			class DigestFields < Split
				# The result of verifying a digest field against a byte stream.
				#
				# The result indicates which byte range was verified ({#scope} and {#byte_range}), and the outcome of each digest entry ({#outcomes}). A result is only {#verified?} when at least one allowed digest entry matched the computed digest; unsupported or failed entries are never reported as verified.
				class Verification
					# The outcome of checking a single digest entry against the computed digest.
					#
					# The status is one of:
					# - :verified - the entry matched the computed digest.
					# - :mismatch - the entry did not match the computed digest.
					# - :unsupported - the algorithm is not supported by this implementation.
					# - :disallowed - the algorithm is not in the allow-list of acceptable algorithms.
					Outcome = Struct.new(:entry, :status, :computed) do
						# Whether the entry matched the computed digest.
						def verified?
							self[:status] == :verified
						end
					end
					
					# A result for a stream that has not finished yet, e.g. when the digest field is conveyed as a trailer.
					def self.pending(scope)
						self.new(scope, status: :pending, reason: "The stream has not finished yet.")
					end
					
					# A result for a digest that cannot be verified, e.g. a repr-digest against partial message content.
					def self.unverifiable(scope, reason)
						self.new(scope, status: :unverifiable, reason: reason)
					end
					
					def initialize(scope, byte_range: nil, outcomes: [], status: nil, reason: nil)
						@scope = scope
						@byte_range = byte_range
						@outcomes = outcomes
						@status = status
						@reason = reason
					end
					
					# @attribute [Symbol] the scope of the verified bytes: :content or :representation.
					attr :scope
					
					# @attribute [Range | Nil] the byte range that was verified.
					attr :byte_range
					
					# @attribute [Array(Outcome)] the outcome of each digest entry.
					attr :outcomes
					
					# @attribute [String | Nil] the reason the digest is pending or unverifiable, if any.
					attr :reason
					
					# The overall status of the verification: :verified, :mismatch, :unsupported, :pending, or :unverifiable.
					def status
						@status ||= begin
							if @outcomes.any?{|outcome| outcome.status == :verified}
								:verified
							elsif @outcomes.any?{|outcome| outcome.status == :mismatch}
								:mismatch
							else
								:unsupported
							end
						end
					end
					
					# Whether at least one allowed digest entry matched the computed digest.
					def verified?
						self.status == :verified
					end
					
					# Whether the stream has not finished yet and no final result is available.
					def pending?
						self.status == :pending
					end
					
					# The algorithm of the first verified entry, if any.
					def algorithm
						if outcome = @outcomes.find{|outcome| outcome.verified?}
							outcome.entry.algorithm
						end
					end
					
					# The outcomes which did not verify (mismatched, disallowed, or unsupported).
					def failures
						@outcomes.reject{|outcome| outcome.verified?}
					end
				end
			end
		end
	end
end
