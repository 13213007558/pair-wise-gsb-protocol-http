
# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "../quoted_string"
require_relative "../error"

module Protocol
	module HTTP
		module Header
			# Represents the WWW-Authenticate (and Proxy-Authenticate) header, which carries one or more authentication challenges.
			#
			# According to <https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1>, the value is a comma-separated list of challenges, where each challenge is an authentication scheme followed by either a token68 or a list of auth-param pairs. As commas separate both challenges and parameters, the value cannot be parsed by splitting on commas: a comma only introduces a new parameter if it is followed by token "=" value, otherwise it introduces a new challenge.
			#
			# The parser preserves the order of challenges, unknown schemes, and duplicate parameters, so that the caller can decide which challenges and parameters are acceptable. It does not select an authentication scheme.
			class WWWAuthenticate < Array
				# Raised when a challenge cannot be parsed, including the precise offset of the syntax error.
				class ParseError < InvalidHeaderError
					# @parameter message [String] a description of the syntax error.
					# @parameter value [String] the raw header value being parsed.
					# @parameter offset [Integer] the byte offset at which the syntax error was encountered.
					def initialize(message, value, offset)
						@value = value
						@offset = offset
						
						super("#{message} at offset #{offset}!")
					end
					
					# @attribute [String] the raw header value being parsed.
					attr :value
					
					# @attribute [Integer] the byte offset of the syntax error within the value.
					attr :offset
					
					# Provides a detailed error message, pointing at the exact location of the syntax error.
					def detailed_message(highlight: false, **options)
						<<~MESSAGE.chomp
							#{super}
								#{@value}
								#{" " * @offset}^
						MESSAGE
					end
				end
				
				# A single authentication challenge: an authentication scheme followed by optional credentials, either a token68 or a list of auth-param pairs.
				class Challenge
					# @parameter scheme [String] the authentication scheme, e.g. "Digest", preserved as sent (schemes are case-insensitive).
					# @parameter token68 [String | Nil] the token68 credentials, if the challenge uses the token68 form.
					# @parameter parameters [Array(Array(String, String)) | Nil] the ordered list of [name, value] auth-param pairs, if the challenge uses the auth-param form. Duplicate names are preserved.
					def initialize(scheme, token68 = nil, parameters = nil)
						@scheme = scheme
						@token68 = token68
						@parameters = parameters
					end
					
					# @attribute [String] the authentication scheme.
					attr :scheme
					
					# @attribute [String | Nil] the token68 credentials.
					attr :token68
					
					# @attribute [Array(Array(String, String)) | Nil] the ordered auth-param pairs.
					attr :parameters
					
					# Whether the challenge uses the token68 form of credentials.
					#
					# @returns [Boolean]
					def token68?
						!@token68.nil?
					end
					
					# Look up the first parameter with the given (case-insensitive) name.
					#
					# @parameter name [String] the parameter name.
					# @returns [String | Nil] the parameter value, if present.
					def [] name
						if @parameters
							@parameters.each do |key, value|
								return value if key.casecmp?(name)
							end
						end
						
						return nil
					end
					
					def == other
						other.is_a?(Challenge) and
							@scheme == other.scheme and
							@token68 == other.token68 and
							@parameters == other.parameters
					end
					
					# The string representation of the challenge, including its credentials.
					#
					# @returns [String]
					def to_s
						if @token68
							"#{@scheme} #{@token68}"
						elsif @parameters and !@parameters.empty?
							parameters = @parameters.map do |key, value|
								"#{key}=#{QuotedString.quote(value)}"
							end
							
							"#{@scheme} #{parameters.join(", ")}"
						else
							@scheme
						end
					end
					
					alias to_str to_s
				end
				
				# Matches optional whitespace (OWS/BWS) at the current offset.
				WHITESPACE = /\G[ \t]*/
				
				# Matches a token at the current offset.
				TOKEN_PATTERN = /\G[!#$%&'*+\-.^_\`~0-9A-Za-z|]+/
				
				# Matches a token68 at the current offset: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
				TOKEN68_PATTERN = /\G[A-Za-z0-9\-._~+\/]+=*/
				
				# Matches a quoted-string at the current offset, including quoted pairs.
				QUOTED_STRING_PATTERN = /\G"(?:[^"\\]|\\.)*"/
				
				# Parses a raw header value into an ordered list of challenges.
				#
				# @parameter value [String] a raw header value containing one or more comma-separated challenges.
				# @returns [WWWAuthenticate] a new instance containing the parsed challenges.
				# @raises [ParseError] if the value contains a syntax error.
				def self.parse(value)
					self.new.tap do |challenges|
						offset = 0
						
						while true
							offset = skip_whitespace(value, offset)
							
							if offset >= value.size
								# Tolerate trailing whitespace and/or a trailing comma:
								break unless challenges.empty?
								
								raise ParseError.new("Expected authentication scheme", value, offset)
							end
							
							offset = parse_challenge(value, offset, challenges)
							
							offset = skip_whitespace(value, offset)
							break if offset >= value.size
							
							if value[offset] == ","
								offset += 1
							else
								raise ParseError.new("Expected ',' between challenges", value, offset)
							end
						end
					end
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
				
				# Adds the challenges from a raw header value to the list.
				#
				# @parameter value [String] a raw header value containing one or more challenges.
				def << value
					self.concat(self.class.parse(value))
				end
				
				# Converts the parsed challenges into a raw header value.
				#
				# @returns [String] a raw header value (comma-separated challenges).
				def to_s
					map(&:to_s).join(", ")
				end
				
				# Whether this header is acceptable in HTTP trailers.
				# @returns [Boolean] false, as authentication challenges are sent before the response body.
				def self.trailer?
					false
				end
				
				# Skip optional whitespace starting at the given offset.
				#
				# @returns [Integer] the offset of the first non-whitespace character.
				def self.skip_whitespace(value, offset)
					WHITESPACE.match(value, offset).end(0)
				end
				
				# Parse a single challenge at the given offset and append it to the list of challenges.
				#
				# @returns [Integer] the offset of the first character after the challenge.
				def self.parse_challenge(value, offset, challenges)
					unless match = TOKEN_PATTERN.match(value, offset)
						raise ParseError.new("Expected authentication scheme", value, offset)
					end
					
					scheme = match[0]
					offset = match.end(0)
					
					token68 = nil
					parameters = nil
					
					# Credentials, if present, must be separated from the scheme by at least one whitespace character:
					if offset < value.size and value[offset] != ","
						whitespace = skip_whitespace(value, offset)
						
						if whitespace > offset
							offset = whitespace
							
							if offset < value.size and value[offset] != ","
								token68, parameters, offset = parse_credentials(value, offset)
							end
						end
					end
					
					challenges.push(Challenge.new(scheme, token68, parameters))
					
					return offset
				end
				
				# Parse the credentials of a challenge: either a token68 or a list of auth-param pairs.
				#
				# @returns [Tuple(String, Nil, Integer) | Tuple(Nil, Array, Integer)] the token68 or parameters, and the offset of the first character after the credentials.
				def self.parse_credentials(value, offset)
					if parameter = scan_parameter(value, offset)
						parameters = [parameter[0]]
						offset = parameter[1]
						
						while true
							comma = skip_whitespace(value, offset)
							break unless value[comma] == ","
							
							candidate = skip_whitespace(value, comma + 1)
							
							# A comma only introduces another parameter if it is followed by an auth-param; otherwise it separates the next challenge:
							if parameter = scan_parameter(value, candidate)
								parameters << parameter[0]
								offset = parameter[1]
							else
								break
							end
						end
						
						return nil, parameters, offset
					else
						unless match = TOKEN68_PATTERN.match(value, offset)
							raise ParseError.new("Expected token68 or auth-param", value, offset)
						end
						
						return match[0], nil, match.end(0)
					end
				end
				
				# Scan a single auth-param (token BWS "=" BWS ( token / quoted-string )) at the given offset.
				#
				# @returns [Tuple(Array(String, String), Integer) | Nil] the [name, value] pair and the offset of the first character after it, or nil if the input at the offset is not an auth-param.
				def self.scan_parameter(value, offset)
					return nil unless match = TOKEN_PATTERN.match(value, offset)
					
					name = match[0]
					offset = skip_whitespace(value, match.end(0))
					
					return nil unless value[offset] == "="
					offset = skip_whitespace(value, offset + 1)
					
					if value[offset] == '"'
						unless match = QUOTED_STRING_PATTERN.match(value, offset)
							raise ParseError.new("Unterminated quoted-string in auth-param", value, offset)
						end
						
						parameter_value = QuotedString.unquote(match[0])
						offset = match.end(0)
					else
						# A missing value means this is not an auth-param (e.g. the trailing "=" of a token68):
						return nil unless match = TOKEN_PATTERN.match(value, offset)
						
						parameter_value = match[0]
						offset = match.end(0)
					end
					
					return [name, parameter_value], offset
				end
			end
		end
	end
end
