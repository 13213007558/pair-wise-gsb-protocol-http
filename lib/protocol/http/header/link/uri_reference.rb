# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Protocol
	module HTTP
		module Header
			class Link
				# A minimal [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) URI reference implementation.
				#
				# It is used to resolve relative link targets and anchors against the request URI without depending on a specific URI library.
				class URIReference
					# Matches the five components of an URI reference: scheme, authority, path, query and fragment.
					PATTERN = /\A(?:(?<scheme>[A-Za-z][A-Za-z0-9+\-.]*):)?(?:\/\/(?<authority>[^\/?#]*))?(?<path>[^?#]*)(?:\?(?<query>[^#]*))?(?:#(?<fragment>.*))?\z/
					
					# Parse an URI reference into its five components.
					#
					# @parameter value [String] an absolute URI or a relative reference.
					# @returns [URIReference] the parsed reference.
					def self.parse(value)
						match = PATTERN.match(value.to_s)
						
						self.new(
							match[:scheme],
							match[:authority],
							match[:path],
							match[:query],
							match[:fragment]
						)
					end
					
					# @parameter scheme [String | Nil] the scheme component.
					# @parameter authority [String | Nil] the authority component.
					# @parameter path [String] the path component.
					# @parameter query [String | Nil] the query component.
					# @parameter fragment [String | Nil] the fragment component.
					def initialize(scheme, authority, path, query = nil, fragment = nil)
						@scheme = scheme&.downcase
						@authority = authority
						@path = path
						@query = query
						@fragment = fragment
					end
					
					# @attribute [String | Nil] the scheme component, normalized to lower case.
					attr :scheme
					
					# @attribute [String | Nil] the authority component.
					attr :authority
					
					# @attribute [String] the path component.
					attr :path
					
					# @attribute [String | Nil] the query component.
					attr :query
					
					# @attribute [String | Nil] the fragment component.
					attr :fragment
					
					# Whether the reference is an absolute URI (i.e. has a scheme).
					#
					# @returns [Boolean] whether the reference has a scheme.
					def absolute?
						!@scheme.nil?
					end
					
					# Resolve this reference against a base URI, according to [RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986#section-5).
					#
					# @parameter base [URIReference] the base URI to resolve against.
					# @returns [URIReference] the resolved, absolute reference.
					def resolve(base)
						base = self.class.parse(base) unless base.is_a?(self.class)
						
						if @scheme
							return self.class.new(@scheme, @authority, remove_dot_segments(@path), @query, @fragment)
						end
						
						if @authority
							return self.class.new(base.scheme, @authority, remove_dot_segments(@path), @query, @fragment)
						end
						
						if @path.empty?
							return self.class.new(
								base.scheme,
								base.authority,
								base.path,
								@query.nil? ? base.query : @query,
								@fragment
							)
						end
						
						if @path.start_with?("/")
							path = remove_dot_segments(@path)
						else
							path = remove_dot_segments(merge_path(base))
						end
						
						return self.class.new(base.scheme, base.authority, path, @query, @fragment)
					end
					
					# Recompose the components into an URI string, according to [RFC 3986 §5.3](https://www.rfc-editor.org/rfc/rfc3986#section-5.3).
					#
					# @returns [String] the recomposed URI reference.
					def to_s
						result = +""
						
						result << "#{@scheme}:" if @scheme
						
						if @authority
							result << "//#{@authority}"
						end
						
						result << @path
						result << "?#{@query}" unless @query.nil?
						result << "##{@fragment}" unless @fragment.nil?
						
						return result
					end
					
					alias to_str to_s
					
				private
				
				# Merge a relative path with the base URI path, according to [RFC 3986 §5.2.3](https://www.rfc-editor.org/rfc/rfc3986#section-5.2.3).
				def merge_path(base)
					if base.authority && base.path.empty?
						return "/#{@path}"
					end
					
					index = base.path.rindex("/")
					
					if index
						base.path[0...index] + "/" + @path
					else
						@path
					end
				end
				
				# Remove `.` and `..` segments from a path, according to [RFC 3986 §5.2.4](https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4).
				def remove_dot_segments(path)
					input = path.dup
					output = +""
					
					while !input.empty?
						if input.start_with?("../")
							input = input[3..]
						elsif input.start_with?("./")
							input = input[2..]
						elsif input.start_with?("/./")
							input[0, 3] = "/"
						elsif input == "/."
							input.replace("/")
						elsif input.start_with?("/../")
							input[0, 4] = "/"
							remove_last_path_segment(output)
						elsif input == "/.."
							input.replace("/")
							remove_last_path_segment(output)
						elsif input == "." || input == ".."
							input.clear
						else
							if index = input.index("/", 1)
								output << input.slice!(0, index)
							else
								output << input
								input.clear
							end
						end
					end
					
						return output
					end
					
					# Pop the last path segment off the output buffer, used when processing `..` segments.
					def remove_last_path_segment(path)
						if index = path.rindex("/")
							path.slice!(index..)
						end
					end
				end
			end
		end
	end
end
