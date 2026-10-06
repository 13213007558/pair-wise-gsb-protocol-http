# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "split"
require_relative "../quoted_string"
require_relative "../error"

require "uri"

module Protocol
	module HTTP
		module Header
			# The `link` header provides a means for serializing one or more links into HTTP headers, as defined by RFC 8288 (Web Linking).
			#
			# Each link-value consists of a target URI-Reference enclosed in angle brackets, followed by optional parameters such as `rel`, `anchor`, `title` and `title*`. The relation (`rel`) parameter may contain multiple space-separated relation types which apply to the same target; they are not split into separate links.
			#
			# ## Examples
			#
			# ```ruby
			# link = Link.parse(%{</style.css>; rel=stylesheet, </page-2>; rel=next; title*=UTF-8''N%c3%a4chstes})
			# link.links.first.target # => "/style.css"
			# link.links.first.relations # => ["stylesheet"]
			# link.links.last.title # => "Nächstes"
			# link.links.last.resolve("https://example.com/") # => #<URI::HTTPS https://example.com/page-2>
			# ```
			class Link < Split
				ParseError = Class.new(InvalidHeaderError)
				
				# A single link-value in the `link` header: a target URI-Reference and its associated parameters.
				class Entry
					# link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
					LINK_VALUE = /\A\s*<(?<target>[^>]*)>(?<parameters>.*)\z/m
					
					# link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
					PARAMETER = /\A\s*(?<name>#{TOKEN})\s*(?:=\s*(?<value>#{TOKEN}|#{QUOTED_STRING})\s*)?\z/
					
					# RFC 8187 ext-value = charset "'" [ language ] "'" value-chars
					EXTENDED_VALUE = /\A(?<charset>#{TOKEN})'(?<language>[^']*)'(?<value>.*)\z/m
					
					# A decoded extended parameter value (e.g. `title*`), retaining the charset and language tag.
					ExtendedValue = Struct.new(:charset, :language, :value)
					
					# Parse a single link-value into an entry.
					#
					# @parameter value [String] a single link-value, e.g. `</style.css>; rel=stylesheet`.
					# @returns [Entry] the parsed link.
					def self.parse(value)
						if match = value.match(LINK_VALUE)
							self.new(match[:target], parse_parameters(match[:parameters]))
						else
							raise ParseError, "Could not parse link value: #{value.inspect}"
						end
					end
					
					# Parse the parameters of a link-value. When a parameter occurs multiple times, the first occurrence is used and subsequent occurrences are ignored, as required by RFC 8288. Syntactically invalid parameters are ignored, as recipients must not fail to parse a link because of such a parameter.
					#
					# @parameter value [String] the parameter portion of a link-value, e.g. `; rel=stylesheet`.
					# @returns [Hash] the parameters, mapping lowercase names to values (or `nil` for valueless parameters).
					def self.parse_parameters(value)
						parameters = {}
						
						Link.split_values(value, ";").each do |part|
							if match = part.match(PARAMETER)
								name = match[:name].downcase
								parameter_value = match[:value]
								
								if parameter_value&.start_with?("\"")
									parameter_value = QuotedString.unquote(parameter_value)
								end
								
								# The first occurrence of a parameter is used; subsequent occurrences are ignored:
								parameters[name] = parameter_value unless parameters.key?(name)
							end
						end
						
						parameters
					end
					
					# Decode an RFC 8187 extended parameter value, e.g. `UTF-8'de'N%c3%a4chstes`.
					#
					# @parameter value [String] the extended value.
					# @returns [ExtendedValue | Nil] the decoded charset, language and value, or `nil` if the value is not a valid extended value.
					def self.parse_extended_value(value)
						if match = value.match(EXTENDED_VALUE)
							charset = match[:charset]
							language = match[:language]
							language = nil if language.empty?
							
							string = value.byteslice(match.begin(:value)...match.end(:value))
							string = string.gsub(/%([0-9A-Fa-f]{2})/){$1.hex.chr(Encoding::BINARY)}.b
							
							if encoding = find_encoding(charset)
								string.force_encoding(encoding)
								string = string.encode(Encoding::UTF_8) unless string.encoding == Encoding::UTF_8
							end
							
							ExtendedValue.new(charset, language, string)
						end
					end
					
					# Look up the Ruby encoding for a charset name, if known.
					#
					# @parameter charset [String] the charset name, e.g. `"UTF-8"`.
					# @returns [Encoding | Nil] the corresponding encoding, or `nil` if unknown.
					def self.find_encoding(charset)
						Encoding.find(charset)
					rescue ArgumentError
						nil
					end
					
					# Create a new link entry.
					#
					# @parameter target [String] the target URI-Reference of the link.
					# @parameter parameters [Hash] the link parameters, mapping lowercase names to values (or `nil` for valueless parameters).
					def initialize(target, parameters = {})
						@target = target
						@parameters = parameters
					end
					
					# @attribute [String] the target URI-Reference of the link.
					attr :target
					
					# @attribute [Hash] all link parameters, including uninterpreted extension parameters, mapping lowercase names to values (or `nil` for valueless parameters).
					attr :parameters
					
					# The set of relation types for this link, from the `rel` parameter. Multiple relation types apply to the same target and are not split into separate links.
					#
					# @returns [Array(String)] the relation types, e.g. `["stylesheet"]`.
					def relations
						if rel = @parameters["rel"]
							rel.split(/\s+/)
						else
							[]
						end
					end
					
					# Whether this link has the given relation type.
					#
					# @parameter relation [String] the relation type, e.g. `"stylesheet"`.
					# @returns [Boolean]
					def relation?(relation)
						relations.include?(relation)
					end
					
					# The `anchor` parameter, which overrides the context of the link.
					#
					# @returns [String | Nil] the anchor URI-Reference, if present.
					def anchor
						@parameters["anchor"]
					end
					
					# The decoded `title*` parameter, including its charset and language tag.
					#
					# @returns [ExtendedValue | Nil] the decoded extended title, or `nil` if not present or invalid.
					def extended_title
						if value = @parameters["title*"]
							self.class.parse_extended_value(value)
						end
					end
					
					# The title of the link. When both `title` and `title*` are present, the decoded `title*` value takes precedence.
					#
					# @returns [String | Nil] the title, if present.
					def title
						if extended_title = self.extended_title
							extended_title.value
						else
							@parameters["title"]
						end
					end
					
					# Access a parameter by name, including extension parameters.
					#
					# @parameter name [String] the parameter name.
					# @returns [String | Nil] the parameter value, or `nil` if not present (or valueless).
					def [](name)
						@parameters[name]
					end
					
					# Create a new entry with the given target and/or parameters changed, leaving all other parameters untouched. Passing `nil` as a parameter value removes the parameter; passing `true` creates a valueless parameter; passing an array joins its elements with a space (e.g. for `rel`).
					#
					# @parameter target [String | Nil] a new target URI-Reference.
					# @parameter changes [Hash] parameter changes, e.g. `rel: "preload"`, `anchor: nil` or `:"title*" => "UTF-8''N%c3%a4chstes"`.
					# @returns [Entry] a new entry with the changes applied.
					def with(target: nil, **changes)
						parameters = @parameters.dup
						
						changes.each do |name, value|
							name = name.to_s.downcase
							
							case value
							when nil
								parameters.delete(name)
							when true
								parameters[name] = nil
							when Array
								parameters[name] = value.join(" ")
							else
								parameters[name] = value.to_s
							end
						end
						
						self.class.new(target || @target, parameters)
					end
					
					# The context of the link: the `anchor` parameter if present (resolved against the request URI if relative), otherwise the request URI itself.
					#
					# @parameter request_uri [String | URI | Nil] the URI of the requested resource, used as the default context and to resolve a relative anchor.
					# @returns [URI::Generic | Nil] the context URI.
					def context(request_uri = nil)
						base = coerce_uri(request_uri) if request_uri
						
						if anchor = self.anchor
							uri = URI.parse(anchor)
							
							if base && uri.relative?
								base.merge(uri)
							else
								uri
							end
						else
							base
						end
					end
					
					# Resolve the target of the link against its context, producing an absolute URI when a request URI (or absolute anchor) is given.
					#
					# @parameter request_uri [String | URI | Nil] the URI of the requested resource.
					# @returns [URI::Generic] the resolved target URI.
					def resolve(request_uri = nil)
						if context = self.context(request_uri)
							context.merge(@target)
						else
							URI.parse(@target)
						end
					end
					
					# Whether this entry is equal to another, comparing target and parameters.
					def ==(other)
						other.is_a?(Entry) && @target == other.target && @parameters == other.parameters
					end
					
					# Convert the link to its string representation, e.g. `</style.css>;rel=stylesheet`.
					#
					# @returns [String] the serialized link-value.
					def to_s
						result = +"<#{@target}>"
						
						@parameters.each do |name, value|
							result << ";#{name}"
							result << "=#{QuotedString.quote(value)}" if value
						end
						
						result
					end
					
				private
					def coerce_uri(value)
						if value.is_a?(URI::Generic)
							value
						else
							URI.parse(value.to_s)
						end
					end
				end
				
				# Parses a raw header value.
				#
				# The value is split into individual link-values on commas, while respecting commas inside quoted strings and angle-bracketed targets.
				#
				# @parameter value [String] a raw header value containing one or more link-values.
				# @returns [Link] a new instance containing the parsed values.
				def self.parse(value)
					self.new(split_values(value))
				end
				
				# Adds one or more link-values to the header.
				#
				# The input string is split into distinct entries, respecting commas inside quoted strings and angle-bracketed targets, and appended to the array.
				#
				# @parameter value [String] a raw header value containing one or more link-values.
				def << value
					self.concat(Link.split_values(value))
				end
				
				# Parse the `link` header value into a list of links.
				#
				# @returns [Array(Entry)] the list of links with their targets and parameters.
				def links
					self.map do |value|
						if value.is_a?(Entry)
							value
						else
							Entry.parse(value)
						end
					end
				end
				
				# Split a header value into individual link-values on the given delimiter, respecting delimiters inside quoted strings and angle-bracketed targets.
				#
				# @parameter value [String] the raw value to split.
				# @parameter delimiter [String] the delimiter to split on, e.g. `","` or `";"`.
				# @returns [Array(String)] the individual values, stripped of surrounding whitespace.
				def self.split_values(value, delimiter = ",")
					values = []
					current = +""
					quoted = false
					escaped = false
					bracketed = false
					
					value.each_char do |char|
						if escaped
							current << char
							escaped = false
						elsif quoted
							current << char
							
							case char
							when "\\"
								escaped = true
							when "\""
								quoted = false
							end
						else
							case char
							when "\""
								quoted = true
								current << char
							when "<"
								bracketed = true
								current << char
							when ">"
								bracketed = false
								current << char
							when delimiter
								if bracketed
									current << char
								else
									values << current.strip
									current = +""
								end
							else
								current << char
							end
						end
					end
					
					values << current.strip
					values.reject!(&:empty?)
					
					values
				end
			end
		end
	end
end
