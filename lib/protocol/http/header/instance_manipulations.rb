# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "split"

module Protocol
	module HTTP
		module Header
			# Represents the `A-IM` and `IM` headers defined by RFC 3229.
			class InstanceManipulations < Split
				# Parse a comma-separated list of instance manipulations.
				#
				# @parameter value [String] a raw header value.
				# @returns [InstanceManipulations] the parsed header.
				def self.parse(value)
					self.new(value.split(COMMA).collect(&:strip))
				end
				
				# Coerce a value into an instance manipulations header.
				#
				# @parameter value [String | Array] the value to coerce.
				# @returns [InstanceManipulations] the parsed header.
				def self.coerce(value)
					case value
					when Array
						self.new(value.map(&:to_s))
					else
						self.parse(value.to_s)
					end
				end
				
				# Add one or more instance manipulation values.
				#
				# @parameter value [String] a comma-separated header value.
				def << value
					self.concat(value.split(COMMA).collect(&:strip))
				end
				
				# Whether the named instance manipulation is acceptable.
				#
				# @parameter name [String] the case-insensitive manipulation name.
				# @returns [Boolean] whether the manipulation is listed.
				def acceptable?(name)
					self.any? {|value| value.split(";", 2).first&.strip&.casecmp?(name)}
				end
			end
		end
	end
end
