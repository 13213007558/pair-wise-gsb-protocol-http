# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "../error"
require_relative "../quoted_string"
require_relative "link/uri_reference"

module Protocol
	module HTTP
		module Header
			# Represents a structured [`link` header](https://www.rfc-editor.org/rfc/rfc8288), as used for web linking.
			#
			# Each link consists of a target URI reference and a set of parameters. Relations (`rel`) are collected into a single set rather than splitting the target into multiple entries, and parameters inside quoted strings may contain commas and semicolons without affecting parsing.
			#
			# ## Examples
			#
			# ```ruby
			# link = Link.parse('</style.css>; rel=stylesheet; title="Default, style"; title*=UTF-8\'\'%E2%9C%A8')
			# link.entries.first.relations # => ["stylesheet"]
			# link.resolve("https://example.com/blog/index") # => ["https://example.com/style.css"]
			# ```
			class Link
				ParseError = Class.new(InvalidHeaderError)
				
				# Parses a raw `link` header value into links.
				#
				# Unlike a naive comma split, this respects quoted strings and angle-bracketed URI references, so a comma inside a quoted parameter value does not split an entry.
				#
				# @parameter value [String] the raw header value.
				# @returns [Link] the parsed links.
				def self.parse(value)
					value = value.to_s.strip
					
					return self.new if value.empty?
					
					entries = self.split_links(value).map! do |part|
						Entry.parse(part)
					end
					
					return self.new(entries)
				end
				
				# Coerces a value into a link header.
				# @parameter value [String | Array | Link] the value to coerce.
				# @returns [Link] the parsed links.
				def self.coerce(value)
					case value
					when self
						return value
					when Array
						return self.new(value.map do |entry|
							entry.is_a?(Entry) ? entry : Entry.parse(entry.to_s)
						end)
					else
						return self.parse(value.to_s)
					end
				end
				
				# Split a raw header value into its individual link-value parts, respecting quoted strings and angle brackets.
				#
				# @parameter value [String] the raw header value.
				# @returns [Array(String)] the individual raw link values.
				def self.split_links(value)
					scan_separators(value, ",")
				end
				
				# @parameter entries [Array(Entry)] the parsed links.
				def initialize(entries = [])
					@entries = entries || []
				end
				
				# @attribute [Array(Entry)] the parsed links.
				attr :entries
				
				# Append a raw or parsed link value.
				# @parameter value [String | Entry] the link to append.
				# @returns [Link] the link header itself.
				def <<(value)
					case value
					when Entry
						@entries << value
					else
						self.class.split_links(value.to_s).each do |part|
							@entries << Entry.parse(part)
						end
					end
					
					return self
				end
				
				# @returns [Integer] the number of links.
				def size
					@entries.size
				end
				
				alias length size
				
				# @returns [Boolean] whether there are no links.
				def empty?
					@entries.empty?
				end
				
				# Iterate over the parsed links.
				def each(&block)
					@entries.each(&block)
				end
				
				include Enumerable
				
				# Look up links by relation type.
				# @parameter relation [String] the relation type (matched case-insensitively).
				# @returns [Array(Entry)] the matching links.
				def [](relation)
					relation = relation.to_s.downcase
					@entries.select{|entry| entry.relations.include?(relation)}
				end
				
				# Convert the links to their wire representation.
				# @returns [String] the serialized header value.
				def to_s
					@entries.map(&:to_s).join(", ")
				end
				
				alias to_str to_s
				
				# Resolve every link target and its context against the given base URI or request.
				#
				# The base URI is the explicit request URI. When a link provides an `anchor`, the anchor is resolved against the request URI first, and then the target is resolved against that context; otherwise the request URI is the context.
				#
				# @parameter base [String | URIReference | Object] the request URI, or an object responding to `scheme`, `authority` and `path`.
				# @returns [Array(String)] the resolved absolute target URIs, in order.
				def resolve(base = nil)
					base = self.class.base_uri(base)
					@entries.map{|entry| entry.resolve(base)}
				end
				
				# Build the base URI from an explicit request URI string or a request-like object.
				# @parameter base [String | URIReference | Object] the request URI or request object.
				# @returns [URIReference] the base URI.
				def self.base_uri(base)
					case base
					when nil
						raise ArgumentError, "A request URI is required to resolve links!"
					when URIReference
						base
					when String
						URIReference.parse(base)
					else
						if base.respond_to?(:scheme)
							scheme = base.scheme
							authority = base.authority
							path = base.path
							
							unless scheme && authority && path
								raise ArgumentError, "Could not derive a request URI from #{base.inspect}!"
							end
							
							URIReference.parse("#{scheme}://#{authority}#{path}")
						else
							raise ArgumentError, "Cannot resolve links against #{base.inspect}!"
						end
					end
				end
				
				# Whether this header is acceptable in HTTP trailers.
				# @returns [Boolean] `false`, as link headers establish metadata before the body is processed.
				def self.trailer?
					false
				end
				
				# Split the parameter portion of a link value on semicolons, respecting quoted strings.
				# @parameter value [String] the raw parameter string, including the leading `;` if present.
				# @returns [Array(String)] the individual raw parameters.
				def self.split_parameters(value)
					scan_separators(value, ";")
				end
				
				# Character-by-character scanner which only treats separators outside quoted strings and angle brackets as delimiters.
				# @parameter value [String] the raw value to scan.
				# @parameter separator [String] the separating character (`","` or `";"`).
				# @returns [Array(String)] the resulting parts.
				def self.scan_separators(value, separator)
					parts = []
					buffer = +""
					# Angle brackets delimit the target URI; quotes delimit parameter string values. They never nest.
					in_angles = false
					in_quotes = false
					escaped = false
					
					value.to_s.each_char do |character|
						if in_quotes
							buffer << character
							
							if escaped
								escaped = false
							elsif character == "\\"
								escaped = true
							elsif character == '"'
								in_quotes = false
							end
						else
							case character
							when '"'
								in_quotes = true
								# Quoted strings only appear in the parameter section, never inside the target reference:
								in_angles = false
								buffer << character
							when "<"
								in_angles = true
								buffer << character
							when ">"
								in_angles = false
								buffer << character
							when separator
								# Separators are only meaningful outside the target URI reference and quoted strings:
								next if in_angles
								parts << buffer.dup
								buffer.clear
								in_angles = false
							else
								buffer << character
							end
						end
					end
					
					parts << buffer
					return parts
				end
				
				# A single parsed link: a target URI reference with its parameters.
				class Entry
					# A link-value starts with an angle-bracketed URI reference.
					TARGET = /\A<(?<target>[^>]*)>(?<parameters>.*)\z/m
					
					# A single `key=value` or valueless parameter.
					PARAMETER = /\A(?<key>#{TOKEN})(?:\s*=\s*(?:(?<quoted>#{QUOTED_STRING})|(?<token>[^;]+?)\s*))?\z/
					
					# An extended parameter value, as defined by [RFC 8187](https://www.rfc-editor.org/rfc/rfc8187#section-3.2.1).
					EXTENDED_VALUE = /\A(?<charset>[A-Za-z][A-Za-z0-9!#$%&+\-^_`{}~]*)'(?<language>[A-Za-z0-9\-]*|\*)'(?<value>[\x21-\x7E]*)\z/
					
					# Parse a single raw link value.
					# @parameter value [String] the raw link value, e.g. `"</style.css>; rel=stylesheet"`.
					# @returns [Entry] the parsed link.
					def self.parse(value)
						match = TARGET.match(value.to_s.strip)
						raise ParseError.new("Could not parse link target: #{value.inspect}") unless match
						
						target = match[:target]
						relations = []
						anchor = nil
						title = nil
						title_localized = nil
						parameters = {}
						
						Link.split_parameters(match[:parameters]).each do |parameter|
							parameter = parameter.strip
							next if parameter.empty?
							
							parameter_match = PARAMETER.match(parameter)
							
							unless parameter_match
								raise ParseError.new("Could not parse link parameter: #{parameter.inspect}")
							end
							
							key = parameter_match[:key].downcase
							value = extract_parameter_value(parameter_match)
							
							# The `anchor` parameter may also be given as an angle-bracketed URI reference:
							value = value[1...-1] if key == "anchor" && value&.start_with?("<") && value.end_with?(">")
							
							case key
							when "rel"
								if value && relations.empty?
									relations = split_relations(value)
								end
							when "anchor"
								anchor ||= value
							when "title"
								title ||= value
							when "title*"
								title_localized ||= parse_extended_value(value) if value
							else
								parameters[key] = value.nil? ? true : value unless parameters.key?(key)
							end
						end
						
						return self.new(
							target,
							relations,
							anchor: anchor,
							title: title,
							title_localized: title_localized,
							parameters: parameters
						)
					end
					
					# @parameter target [String] the target URI reference.
					# @parameter relations [Array(String)] the relation types, normalized to lower case.
					# @parameter anchor [String | Nil] the context URI override.
					# @parameter title [String | Nil] the human-readable title.
					# @parameter title_localized [LocalizedValue | Nil] the charset/language tagged title.
					# @parameter parameters [Hash] the remaining extension parameters.
					def initialize(target, relations = [], anchor: nil, title: nil, title_localized: nil, parameters: {})
						@target = target
						@relations = relations
						@anchor = anchor
						@title = title
						@title_localized = title_localized
						@parameters = parameters
					end
					
					# @attribute [String] the target URI reference exactly as received.
					attr :target
					
					# @attribute [Array(String)] the relation types, normalized to lower case and deduplicated.
					attr :relations
					
					# @attribute [String | Nil] the raw `anchor` parameter.
					attr :anchor
					
					# @attribute [String | Nil] the raw `title` parameter.
					attr :title
					
					# @attribute [LocalizedValue | Nil] the parsed `title*` parameter.
					attr :title_localized
					
					# @attribute [Hash] the extension parameters which aren't interpreted specially.
					attr :parameters
					
					# @returns [String] the most appropriate title available, preferring the localized `title*` value.
					def title
						if @title_localized
							return @title_localized.value
						end
						
						return @title
					end
					
					# Whether the link carries the given relation type. Comparison is case-insensitive.
					# @parameter relation [String] the relation type.
					# @returns [Boolean] whether the relation is present.
					def relation?(relation)
						@relations.include?(relation.to_s.downcase)
					end
					
					# Fetch an extension parameter by name.
					# @parameter key [String] the parameter name.
					# @returns [String | LocalizedValue | Nil] the parameter value.
					def [](key)
						@parameters[key.to_s.downcase]
					end
					
					# Resolve the link context (the effective anchor) against the request URI.
					# @parameter base [URIReference] the request URI.
					# @returns [URIReference] the resolved context URI.
					def context(base)
						if @anchor
							return resolve_reference(@anchor, base)
						end
						
						return base
					end
					
					# Resolve the target URI against the link context derived from the request URI.
					# @parameter base [String | URIReference | Object] the request URI or request object.
					# @returns [String] the resolved absolute target URI.
					def resolve(base)
						base = Link.base_uri(base)
						return resolve_reference(@target, context(base)).to_s
					end
					
					# Return a copy of this link with a single parameter changed or removed.
					#
					# Pass `nil` to remove the parameter. Extension parameters are modified by name; `rel`, `anchor`, `title` and `title*` update the corresponding structured attributes.
					#
					# @parameter key [String | Symbol] the parameter name, e.g. `:rel`, `"title"`, `"crossorigin"`.
					# @parameter value [String | Array(String) | LocalizedValue | Nil] the new value, or `nil` to remove.
					# @returns [Entry] an updated copy; the original link is not modified.
					def with_parameter(key, value = nil)
						dup.set_parameter!(key, value)
					end
					
					# Set or remove a single parameter in place.
					# @parameter key [String | Symbol] the parameter name.
					# @parameter value [String | Array(String) | LocalizedValue | Nil] the new value, or `nil` to remove.
					# @returns [Entry] the link itself.
					def set_parameter!(key, value = nil)
						case key.to_s.downcase
						when "rel"
							@relations = value ? Array(value).flat_map{|entry| entry.to_s.split(/\s+/).reject(&:empty?).map(&:downcase)}.uniq : []
						when "anchor"
							@anchor = value&.to_s
						when "title"
							@title = value&.to_s
						when "title*"
							@title_localized = value
						else
							name = key.to_s.downcase
							
							if value.nil?
								@parameters.delete(name)
							else
								@parameters[name] = value
							end
						end
						
						return self
					end
					
					# Initialize a copy with independent parameter containers.
					def initialize_dup(other)
						super
						@relations = @relations.dup
						@parameters = @parameters.dup
					end
					
					# Serialize the link to its wire representation.
					# @returns [String] the serialized link value.
					def to_s
						parts = ["<#{@target}>"]
						parts << "rel=#{QuotedString.quote(@relations.join(" "), true)}" unless @relations.empty?
						parts << "anchor=#{format_anchor(@anchor)}" if @anchor
						parts << "title=#{QuotedString.quote(@title, true)}" if @title
						parts << "title*=#{@title_localized}" if @title_localized
						
						@parameters.each do |key, value|
							if value == true
								parts << key
							else
								parts << "#{key}=#{format_parameter_value(value)}"
							end
						end
						
						return parts.join("; ")
					end
					
					alias to_str to_s
					
					# Compare with another link by target and parsed parameters.
					def ==(other)
						return false unless other.is_a?(self.class)
						
						return target == other.target &&
							relations == other.relations &&
							anchor == other.anchor &&
							@title == other.instance_variable_get(:@title) &&
							@title_localized == other.title_localized &&
							parameters == other.parameters
					end
					
					class << self
						private
						
						# Extract the raw value of a parsed parameter, unquoting quoted strings.
						def extract_parameter_value(match)
							if quoted = match[:quoted]
								return QuotedString.unquote(quoted)
							end
							
							return match[:token]
						end
						
						# Split a relation value into its relation types, normalized to lower case and deduplicated while preserving order.
						def split_relations(value)
							value.split(/\s+/).reject(&:empty?).map(&:downcase).uniq
						end
						
						# Parse an RFC 8187 extended value, returning `nil` if it cannot be interpreted.
						def parse_extended_value(value)
							match = EXTENDED_VALUE.match(value)
							return nil unless match
							
							charset = match[:charset].downcase
							language = match[:language].empty? ? nil : match[:language]
							decoded = percent_decode(match[:value].b)
							
							unless charset == "utf-8" || charset == "us-ascii"
								decoded = convert_charset(decoded, charset)
							end
							
							decoded.force_encoding("UTF-8")
							
							unless decoded.valid_encoding?
								raise Encoding::InvalidByteSequenceError
							end
							
							return LocalizedValue.new(decoded, language, charset)
						rescue ArgumentError, Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError
							return nil
						end
						
						# Percent-decode into a binary string.
						def percent_decode(value)
							decoded = +""
							
							while !value.empty?
								if value.start_with?("%")
									hex = value[1, 2]
									
									unless hex && hex.match?(/\A[0-9A-Fa-f]{2}\z/)
										raise ArgumentError, "Invalid percent encoding: #{value[0, 3].inspect}"
									end
									
									decoded << hex.to_i(16).chr
									value = value[3..]
								else
									decoded << value[0]
									value = value[1..]
								end
							end
							
							return decoded
						end
						
						# Convert a byte string from the given charset into UTF-8, when Ruby knows the encoding.
						def convert_charset(bytes, charset)
							encoding = Encoding.find(charset)
							return bytes.encode("UTF-8", encoding)
						rescue ArgumentError
							return bytes
						end
					end
					
					private
					
					# Resolve one URI reference against a base.
					def resolve_reference(reference, base)
						URIReference.parse(reference).resolve(base)
					end
					
					# Serialize an anchor value. URI references are serialized as quoted strings as required by [RFC 8288](https://www.rfc-editor.org/rfc/rfc8288#section-3.4.1).
					def format_anchor(anchor)
						QuotedString.quote(anchor, true)
					end
					
					# Serialize an extension parameter value.
					def format_parameter_value(value)
						case value
						when LocalizedValue
							value.to_s
						else
							QuotedString.quote(value.to_s)
						end
					end
				end
				
				# An extended parameter value carrying charset and language information, as defined by [RFC 8187](https://www.rfc-editor.org/rfc/rfc8187).
				class LocalizedValue
					# Characters which may appear without percent encoding in an extended parameter value.
					ATTR_CHAR = /[A-Za-z0-9!#$&+\-.^_`|~]/
					
					# @parameter value [String] the decoded value.
					# @parameter language [String | Nil] the language tag, e.g. `"en"` or `"zh-CN"`.
					# @parameter charset [String] the charset, defaulting to UTF-8.
					def initialize(value, language = nil, charset = "utf-8")
						@value = value
						@language = language
						@charset = charset
					end
					
					# @attribute [String] the decoded value.
					attr :value
					
					# @attribute [String | Nil] the language tag.
					attr :language
					
					# @attribute [String] the charset, normalized to lower case.
					attr :charset
					
					# Serialize to an RFC 8187 `ext-value`.
					# @returns [String] the encoded value, e.g. `UTF-8'en'%E2%9C%A8`.
					def to_s
						encoded = +""
						
						@value.b.each_char do |byte|
							if ATTR_CHAR.match?(byte)
								encoded << byte
							else
								encoded << "%#{byte.unpack1("H2").upcase}"
							end
						end
						
						return "#{@charset.upcase}'#{@language || ""}'#{encoded}"
					end
					
					alias to_str to_s
					
					# Compare with another localized value.
					def ==(other)
						self.class == other.class &&
							value == other.value &&
							language == other.language &&
							charset == other.charset
					end
				end
			end
		end
	end
end
