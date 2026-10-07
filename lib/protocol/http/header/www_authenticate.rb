# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "../quoted_string"
require_relative "../error"

module Protocol
	module HTTP
		module Header
			# Represents the `www-authenticate` header, which is an ordered list of challenges.
			#
			# According to <https://www.rfc-editor.org/rfc/rfc9110#section-11.3>:
			#
			# ```
			# WWW-Authenticate = 1#challenge
			# challenge        = auth-scheme [ 1*SP ( token68 / [ auth-param *( OWS "," OWS auth-param ) ] ) ]
			# auth-param       = token BWS "=" BWS ( token / quoted-string )
			# token68          = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
			# ```
			#
			# A single header field may contain multiple challenges, and several `www-authenticate` fields may be combined into one, so commas can separate both challenges and the parameters within a challenge. Because of this, the value cannot be parsed by simply splitting on commas or equals signs; this parser walks the value and assigns each comma and equals sign to the correct production.
			#
			# The parser preserves unknown schemes and duplicate parameters in their original order, so that the caller can decide which challenge (if any) to accept. It does not select an authentication scheme on your behalf.
			class WWWAuthenticate < Array
				# Raised when a `www-authenticate` header value contains a syntax error. Carries the exact offset of the error within the original value.
				class ParseError < InvalidHeaderError
					# @parameter message [String] a description of the syntax error.
					# @parameter value [String] the original header value.
					# @parameter offset [Integer] the byte offset at which the error was detected.
					def initialize(message, value, offset)
						@value = value
						@offset = offset
						
						super("#{message} at offset #{offset}: #{value.inspect}")
					end
					
					# @attribute [String] the original header value.
					attr :value
					
					# @attribute [Integer] the byte offset of the syntax error within the value.
					attr :offset
				end
				
				# A single authentication challenge, consisting of a scheme and either a token68 credential or an ordered list of parameters.
				class Challenge
					# @parameter scheme [String] the authentication scheme, e.g. `"Digest"`. Unknown schemes are preserved as-is.
					# @parameter parameters [Array] an ordered list of `[name, value]` pairs. Duplicate names are preserved.
					# @parameter token68 [String | Nil] the token68 credentials, if the challenge uses that form.
					def initialize(scheme, parameters = [], token68: nil)
						if token68 and !parameters.empty?
							raise ArgumentError, "A challenge cannot have both token68 credentials and parameters!"
						end
						
						@scheme = scheme
						@parameters = parameters
						@token68 = token68
					end
					
					# @attribute [String] the authentication scheme.
					attr :scheme
					
					# @attribute [Array] the ordered list of `[name, value]` parameter pairs, including any duplicates.
					attr :parameters
					
					# @attribute [String | Nil] the token68 credentials, if present.
					attr :token68
					
					# Set the token68 credentials.
					attr_writer :token68
					
					# @returns [Boolean] whether the challenge uses the token68 form.
					def token68?
						!@token68.nil?
					end
					
					# Look up the first parameter with the given (case-insensitive) name. As duplicate parameters are preserved, use {#parameters} directly if you need to disambiguate.
					#
					# @parameter name [String] the parameter name.
					# @returns [String | Nil] the parameter value, or `nil` if not present.
					def [] name
						if pair = @parameters.find{|key, _| key.casecmp?(name)}
							pair.last
						end
					end
					
					# Converts the challenge into its raw header representation.
					#
					# @returns [String] the serialized challenge.
					def to_s
						if token68 = @token68
							"#{@scheme} #{token68}"
						elsif @parameters.empty?
							@scheme
						else
							parameters = @parameters.map do |key, value|
								"#{key}=#{QuotedString.quote(value.to_s)}"
							end
							
							"#{@scheme} #{parameters.join(", ")}"
						end
					end
					
					# Compare two challenges for equality, including scheme, token68 and parameters (in order).
					def == other
						other.is_a?(Challenge) and
							@scheme == other.scheme and
							@token68 == other.token68 and
							@parameters == other.parameters
					end
				end
				
				# Matches a `token` (scheme or parameter name/value), per RFC 9110.
				TOKEN = /[!#$%&'*+\-.^_`|~0-9A-Za-z]+/
				
				# Matches a `quoted-string` parameter value, per RFC 9110.
				QUOTED_STRING = /"(?:[^"\\]|\\.)*"/
				
				# Matches a `token68` credential, per RFC 9110.
				TOKEN68 = /[A-Za-z0-9\-._~+\/]+=*/
				
				# Matches a complete `auth-param` production.
				AUTH_PARAM = /(#{TOKEN})[ \t]*=[ \t]*(#{QUOTED_STRING}|#{TOKEN})/
				
				# Parses a raw header value into an ordered list of challenges.
				#
				# @parameter value [String] a raw header value containing one or more challenges.
				# @raises [ParseError] if the value contains a syntax error, with the precise offset.
				# @returns [WWWAuthenticate] a new instance containing the parsed challenges.
				def self.parse(value)
					challenges = self.new
					offset = 0
					
					while true
						offset = skip_whitespace(value, offset)
						
						break if offset >= value.length
						
						# Skip empty list elements, as permitted by the `#rule`:
						if value[offset] == ","
							offset += 1
							next
						end
						
						challenge, offset = parse_challenge(value, offset)
						challenges << challenge
						
						offset = skip_whitespace(value, offset)
						
						break if offset >= value.length
						
						if value[offset] == ","
							offset += 1
						else
							raise ParseError.new("Expected ',' between challenges", value, offset)
						end
					end
					
					if challenges.empty?
						raise ParseError.new("Expected at least one challenge", value, 0)
					end
					
					return challenges
				end
				
				# Coerces a value into a parsed header object.
				#
				# @parameter value [String | Array] the value to coerce.
				# @returns [WWWAuthenticate] a parsed header object.
				def self.coerce(value)
					case value
					when Array
						self.new(value)
					else
						self.parse(value.to_s)
					end
				end
				
				# Converts the parsed header value into a raw header value.
				#
				# @returns [String] a raw header value (comma-separated challenges).
				def to_s
					map(&:to_s).join(", ")
				end
				
				# Whether this header is acceptable in HTTP trailers.
				# @returns [Boolean] `false`, as authentication challenges are sent before the response body.
				def self.trailer?
					false
				end
				
				# @private
				def self.skip_whitespace(value, offset)
					if match = value.match(/\G[ \t]+/, offset)
						match.end(0)
					else
						offset
					end
				end
				
				# @private
				def self.parse_challenge(value, offset)
					if match = value.match(/\G#{TOKEN}/, offset)
						scheme = match[0]
						offset = match.end(0)
					else
						raise ParseError.new("Expected authentication scheme", value, offset)
					end
					
					challenge = Challenge.new(scheme)
					
					if whitespace = value.match(/\G[ \t]+/, offset)
						offset = whitespace.end(0)
						
						# A challenge may have no credentials at all:
						return challenge, offset if offset >= value.length or value[offset] == ","
						
						if value.match(/\G#{AUTH_PARAM}/, offset)
							offset = parse_parameters(challenge, value, offset)
						elsif match = value.match(/\G#{TOKEN68}/, offset)
							challenge.token68 = match[0]
							offset = match.end(0)
						else
							raise ParseError.new("Expected token68 or auth-param", value, offset)
						end
					elsif offset < value.length and value[offset] != ","
						raise ParseError.new("Expected whitespace after authentication scheme", value, offset)
					end
					
					return challenge, offset
				end
				
				# Parse the parameters of a challenge, stopping at the comma which separates this challenge from the next one.
				#
				# @private
				def self.parse_parameters(challenge, value, offset)
					while match = value.match(/\G#{AUTH_PARAM}/, offset)
						name = match[1]
						raw_value = match[2]
						
						parameter_value = raw_value.start_with?('"') ? QuotedString.unquote(raw_value) : raw_value
						
						challenge.parameters << [name, parameter_value]
						offset = match.end(0)
						
						offset = skip_whitespace(value, offset)
						
						# A comma may either separate parameters within this challenge, or mark the start of the next challenge:
						break unless offset < value.length and value[offset] == ","
						
						lookahead = skip_whitespace(value, offset + 1)
						
						# The comma only belongs to this challenge if another complete auth-param follows:
						break unless value.match(/\G#{AUTH_PARAM}/, lookahead)
						
						offset = lookahead
					end
					
					return offset
				end
			end
		end
	end
end
