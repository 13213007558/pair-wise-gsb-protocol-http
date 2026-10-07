# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "error"
require "stringio"

module Protocol
	module HTTP
		# A small RFC 3284 VCDIFF encoder and decoder.
		module VCDiff
			MAGIC = "\xD6\xC3\xC4\x00".b
			
			VCD_DECOMPRESS = 0x01
			VCD_CODETABLE = 0x02
			VCD_APPHEADER = 0x04
			VCD_SOURCE = 0x01
			VCD_TARGET = 0x02
			VCD_CHECKSUM = 0x04
			
			NUMBER_OF_MODES = 9
			NUMBER_OF_NEAR_CACHES = 4
			SAME_CACHE_MASK = 255
			
			DEFAULT_ADD_SIZE = 18
			DEFAULT_COPY_SIZE = 18
			DEFAULT_RUN_SIZE = 9
			
			ADD = 0
			COPY = 1
			RUN = 2
			
			Operation = Struct.new(:type, :size, :mode, :inline_size)
			
			# Encode a target representation relative to a caller-supplied source representation.
			#
			# @parameter source [String] the base representation.
			# @parameter target [String] the complete new representation.
			# @returns [String] VCDIFF data using the default code table and no secondary compression.
			def self.encode(source, target)
				self::Encoder.new(source, target).encode
			end
			
			# Decode VCDIFF data using a caller-supplied source representation.
			#
			# @parameter source [String] the expected base representation.
			# @parameter data [String] VCDIFF data.
			# @returns [String] the complete target representation.
			# @raises [VCDiffError] if the data is malformed or uses an unsupported feature.
			def self.decode(source, data)
				self::Decoder.new(source, data).decode
			end
			
			# @private
			def self.default_code_table
				table = Array.new(256)
				
				table[0] = [Operation.new(ADD, 0, 0, true)]
				(1...DEFAULT_ADD_SIZE).each do |size|
					table[size] = [Operation.new(ADD, size, 0, true)]
				end
				
				table[DEFAULT_ADD_SIZE] = [Operation.new(RUN, 0, 0, true)]
				(1...DEFAULT_RUN_SIZE).each do |size|
					index = DEFAULT_ADD_SIZE + size
					table[index] = [Operation.new(RUN, size, 0, true)]
				end
				
				copy_start = DEFAULT_ADD_SIZE + DEFAULT_RUN_SIZE
				(1...DEFAULT_COPY_SIZE).each do |size|
					NUMBER_OF_MODES.times do |mode|
						index = copy_start + (size - 1) * NUMBER_OF_MODES + mode
						table[index] = [Operation.new(COPY, size, mode, true)]
					end
				end

				NUMBER_OF_MODES.times do |mode|
					index = copy_start + (DEFAULT_COPY_SIZE - 1) * NUMBER_OF_MODES + mode
					table[index] = [Operation.new(COPY, 0, mode, true)]
				end
				
				index = copy_start + NUMBER_OF_MODES * DEFAULT_COPY_SIZE
				6.times do |copy_size|
					NUMBER_OF_MODES.times do |mode|
						table[index] = [
							Operation.new(COPY, copy_size + 1, mode, true),
							Operation.new(ADD, 0, 0, false)
						]
						index += 1
					end
				end
				
				9.times do |mode|
					table[index] = [
						Operation.new(ADD, 0, 0, false),
						Operation.new(COPY, 1, mode, true)
					]
					index += 1
				end

				3.times do |mode|
					table[index] = [
						Operation.new(COPY, 7, mode, true),
						Operation.new(ADD, 0, 0, false)
					]
					index += 1
				end

				table[index] = [
					Operation.new(ADD, 1, 0, true),
					Operation.new(COPY, 1, 0, true)
				]
				index += 1
				
				raise "unexpected code table size: #{index}" unless index == 256
				return table.freeze
			end
			
			DEFAULT_CODE_TABLE = default_code_table
			
			# @private
			module IntegerCoding
				def encode_integer(value, output)
					raise VCDiffError, "Invalid integer: #{value}" unless value.is_a?(Integer) && value >= 0
					
					digits = []
					begin
						digits << (value & 0x7F)
						value >>= 7
					end while value > 0
					
					digits.each_with_index do |digit, index|
						output << (digit | (index + 1 == digits.length ? 0 : 0x80)).chr
					end
				end
				
				def decode_integer(input, limit = nil)
					value = 0
					bytes = 0
					
					loop do
						raise VCDiffError, "Truncated VCDIFF integer" if input.eof?
						raise VCDiffError, "VCDIFF integer is too large" if bytes >= 10
						if limit && input.pos >= limit
							raise VCDiffError, "VCDIFF section length is invalid"
						end
						
						byte = input.readbyte
						value = (value << 7) | (byte & 0x7F)
						bytes += 1
						return value if byte.nobits?(0x80)
					end
				end
			end
			
			# @private
			class Encoder
				include IntegerCoding
				
				MINIMUM_MATCH = 3
				MAXIMUM_LITERAL = 17
				MAXIMUM_CANDIDATES = 64
				
				def initialize(source, target)
					@source = binary(source)
					@target = binary(target)
					
					@source_positions = Hash.new{|hash, key| hash[key] = []}
					build_source_positions
				end
				
				def encode
					instructions = String.new.b
					addresses = String.new.b
					data = String.new.b
					target_positions = Hash.new{|hash, key| hash[key] = []}
					
					position = 0
					while position < @target.bytesize
						add_target_position(target_positions, position)
						
						match = find_match(position, target_positions)
						if match
							address, length = match
							emit_copy(instructions, addresses, address, length, position)
							new_position = position + length
							add_target_positions(target_positions, position, new_position)
							position = new_position
						else
							start = position
							begin
								position += 1
								add_target_position(target_positions, position) if position < @target.bytesize
							end while position < start + MAXIMUM_LITERAL && position < @target.bytesize && find_match(position, target_positions).nil?
							chunk = @target.byteslice(start, position - start)
							emit_add(instructions, data, chunk)
						end
					end

					window = encode_window(instructions, data, addresses)
					MAGIC + 0.chr + window
				end
				
				private
				
				def binary(value)
					raise ArgumentError, "Expected a String" unless value.is_a?(String)
					value.b.dup
				end
				
				def build_source_positions
					return if @source.bytesize < MINIMUM_MATCH
					(0..@source.bytesize - MINIMUM_MATCH).each do |position|
						@source_positions[@source.byteslice(position, MINIMUM_MATCH)] << position
					end
				end

				def add_target_position(target_positions, position)
					return if position < MINIMUM_MATCH
					
					key = @target.byteslice(position - MINIMUM_MATCH, MINIMUM_MATCH)
					target_positions[key] << @source.bytesize + position - MINIMUM_MATCH
				end

				def add_target_positions(target_positions, start_position, end_position)
					((start_position + MINIMUM_MATCH)..end_position).each do |position|
						add_target_position(target_positions, position)
					end
				end
				
				def find_match(position, target_positions)
					return nil if position + MINIMUM_MATCH > @target.bytesize
					
					key = @target.byteslice(position, MINIMUM_MATCH)
					candidates = @source_positions[key] + target_positions.fetch(key, [])
					return nil if candidates.empty?
					
					best_address = nil
					best_length = 0
					candidates.last(MAXIMUM_CANDIDATES).each do |address|
						next if address >= @source.bytesize + position
						maximum_length = if address < @source.bytesize
							@source.bytesize - address
						else
							position - (address - @source.bytesize)
						end
						next if maximum_length < MINIMUM_MATCH
						length = match_length(address, position)
						length = [length, maximum_length].min
						next if length < MINIMUM_MATCH
						if length > best_length || (length == best_length && address < (best_address || Float::INFINITY))
							best_address = address
							best_length = length
						end
					end
					
					best_address && [best_address, best_length]
				end
				
				def match_length(address, position)
					length = 0
					limit = @target.bytesize - position
					if address < @source.bytesize
						limit = [limit, @source.bytesize - address].min
					end
					while length < limit
						byte = if address + length < @source.bytesize
							@source.getbyte(address + length)
						else
							target_offset = address + length - @source.bytesize
							break if target_offset > position + length
							@target.getbyte(target_offset)
						end
						break unless byte == @target.getbyte(position + length)
						length += 1
					end
					length
				end
				
				def emit_add(instructions, data, chunk)
					if chunk.bytesize < DEFAULT_ADD_SIZE && chunk.bytesize > 0
						instructions << chunk.bytesize.chr
					else
						instructions << 0.chr
						encode_integer(chunk.bytesize, instructions)
					end
					data << chunk
				end
				
				def emit_copy(instructions, addresses, address, length, target_position)
					mode = 0
					encoded_address = address
					if address >= @source.bytesize
						mode = 1
						encoded_address = @source.bytesize + target_position - address - 1
					end
					
					copy_start = DEFAULT_ADD_SIZE + DEFAULT_RUN_SIZE
					if length >= 1 && length < DEFAULT_COPY_SIZE
						instructions << (copy_start + (length - 1) * NUMBER_OF_MODES + mode).chr
					else
						copy_index = copy_start + (DEFAULT_COPY_SIZE - 1) * NUMBER_OF_MODES + mode
						instructions << copy_index.chr
						encode_integer(length, instructions)
					end
					encode_integer(encoded_address, addresses)
				end
				
				def encode_window(instructions, data, addresses)
					delta = String.new.b
					encode_integer(data.bytesize, delta)
					encode_integer(instructions.bytesize, delta)
					encode_integer(addresses.bytesize, delta)
					encode_integer(@target.bytesize, delta)
					delta << data
					delta << instructions
					delta << addresses
					
					window = String.new.b
					window << VCD_SOURCE.chr
					window << encode_integer_string(@source.bytesize)
					window << encode_integer_string(0)
					window << encode_integer_string(delta.bytesize)
					window << delta
					window
				end
				
				def encode_integer_string(value)
					result = String.new.b
					encode_integer(value, result)
					result
				end
			end

			# @private
			class Decoder
				include IntegerCoding
				
				def initialize(source, data)
					@source = binary(source)
					@data = binary(data)
					@input = StringIO.new(@data)
				end
				
				def position
					@input.pos
				end
				
				def decode
					read_header
					
					target = String.new.b
					until @input.eof?
						target << read_window
					end
					target
				end
				
				private
				
				def binary(value)
					raise ArgumentError, "Expected a String" unless value.is_a?(String)
					value.b.dup
				end
				
				def read_header
					magic = read_bytes(MAGIC.bytesize)
					raise VCDiffError, "Invalid VCDIFF magic" unless magic == MAGIC
					
					flags = read_byte
					unsupported = VCD_DECOMPRESS | VCD_CODETABLE | VCD_APPHEADER
					if (flags & unsupported) != 0
						raise VCDiffError, "Unsupported VCDIFF header features: 0x#{flags.to_s(16)}"
					end
					raise VCDiffError, "Invalid VCDIFF header flags: 0x#{flags.to_s(16)}" unless flags == 0
				end
				
				def read_window
					flags = read_byte
					if (flags & ~(VCD_SOURCE | VCD_TARGET | VCD_CHECKSUM)) != 0
						raise VCDiffError, "Unsupported VCDIFF window flags: 0x#{flags.to_s(16)}"
					end
					raise VCDiffError, "VCDIFF checksums are unsupported" if (flags & VCD_CHECKSUM) != 0
					
					case flags & (VCD_SOURCE | VCD_TARGET)
					when VCD_SOURCE
						source_length = decode_integer(@input)
						source_position = decode_integer(@input)
						if source_length > @source.bytesize || source_position + source_length > @source.bytesize
							raise VCDiffError, "Invalid VCDIFF source segment"
						end
						source = @source.byteslice(source_position, source_length)
					when 0
						source = String.new.b
					else
						raise VCDiffError, "VCDIFF target windows are unsupported"
					end
					
					delta_length = decode_integer(@input)
					delta_limit = position + delta_length
					raise VCDiffError, "Truncated VCDIFF window" if delta_limit > @data.bytesize

					add_data_length = decode_integer(@input, delta_limit)
					instructions_length = decode_integer(@input, delta_limit)
					addresses_length = decode_integer(@input, delta_limit)
					target_length = decode_integer(@input, delta_limit)
					
					sections_limit = position + add_data_length + instructions_length + addresses_length
					if sections_limit != delta_limit
						raise VCDiffError, "Invalid VCDIFF section lengths"
					end
					
					add_data_bytes = read_bytes(add_data_length, sections_limit)
					add_data = LimitedIO.new(add_data_bytes, add_data_length)
					instructions_offset = position
					addresses_offset = instructions_offset + instructions_length
					@input.seek(sections_limit)
					instructions = LimitedIO.new(@data, instructions_length, instructions_offset)
					addresses = LimitedIO.new(@data, addresses_length, addresses_offset)
					target = String.new.b
					near = Array.new(NUMBER_OF_NEAR_CACHES, 0)
					same = Array.new(SAME_CACHE_MASK + 1, 0)
					
					until instructions.eof?
						opcode = instructions.readbyte
						table = VCDiff::DEFAULT_CODE_TABLE.fetch(opcode) do
							raise VCDiffError, "Invalid VCDIFF opcode: #{opcode}"
						end
						
						table.each do |operation|
							size = operation.size
							if operation.inline_size && size == 0
								size = decode_integer(instructions)
								raise VCDiffError, "Invalid VCDIFF zero-length operation" if size == 0
							end
							
							case operation.type
							when ADD
								target << read_operation_bytes(add_data, size, "ADD")
							when RUN
								byte = read_operation_bytes(add_data, 1, "RUN")
								target << byte * size
							when COPY
								encoded_address = decode_integer(addresses)
								address = decode_copy_address(encoded_address, operation.mode, target, near, same)
								append_copy(source, target, address, size)
							else
								raise VCDiffError, "Unsupported VCDIFF operation: #{operation.type}"
							end
						end
				end
					
					raise VCDiffError, "Unconsumed VCDIFF instruction data" unless instructions.eof?
					raise VCDiffError, "Unconsumed VCDIFF address data" unless addresses.eof?
					raise VCDiffError, "Invalid VCDIFF delta length" unless @input.pos == delta_limit
					raise VCDiffError, "Invalid VCDIFF target length" unless target.bytesize == target_length
					target
				end
				
				def decode_copy_address(encoded, mode, target, near, same)
					case mode
					when 0
						address = encoded
					when 1
						address = @source.bytesize + target.bytesize - encoded - 1
					when 2...(2 + NUMBER_OF_NEAR_CACHES)
						cache = mode - 2
						address = near[cache] + encoded
					else
						cache = mode - (2 + NUMBER_OF_NEAR_CACHES)
						unless (0...3).cover?(cache)
							raise VCDiffError, "Unsupported VCDIFF address mode: #{mode}"
						end
						slot = encoded & SAME_CACHE_MASK
						address = same[slot] + encoded
					end
					
					if mode >= 2 && mode < 2 + NUMBER_OF_NEAR_CACHES
						near[mode - 2] = address
					elsif mode >= 2 + NUMBER_OF_NEAR_CACHES
						same[slot] = address
					end
					
					address
				end
				
				def append_copy(source, target, address, length)
					available = source.bytesize + target.bytesize
					if address >= available || address < 0 || length <= 0
						raise VCDiffError, "Invalid VCDIFF COPY address or length"
					end
					
					length.times do |offset|
						absolute = address + offset
						if absolute < source.bytesize
							target << source.byteslice(absolute, 1)
						else
							target_offset = address - source.bytesize + offset
							raise VCDiffError, "Invalid VCDIFF target COPY" if target_offset < 0 || target_offset >= target.bytesize
							target << target.byteslice(target_offset, 1)
						end
					end
				end
				
				def read_operation_bytes(input, length, name)
					raise VCDiffError, "Invalid VCDIFF #{name} length" if length > input.remaining
					input.read(length) || raise(VCDiffError, "Truncated VCDIFF #{name} data")
				end
				
				def read_bytes(length, limit = nil)
					if limit
						raise VCDiffError, "VCDIFF section length is invalid" if position + length > limit
					end
					raise VCDiffError, "Truncated VCDIFF data" if position + length > @data.bytesize
					@input.read(length) || raise(VCDiffError, "Truncated VCDIFF data")
				end
				
				def read_byte
					raise VCDiffError, "Truncated VCDIFF data" if @input.eof?
					@input.readbyte
				end
			end

			# @private
			class LimitedIO
				def initialize(data, length, offset = 0)
					@data = data
					@remaining = length
					@offset = offset
				end
				
				attr :remaining
				
				def pos
					@offset
				end
				
				def eof?
					@remaining == 0 || @offset >= @data.bytesize
				end
				
				def read(length)
					raise VCDiffError, "Truncated VCDIFF section" if length > @remaining
					@remaining -= length
					value = @data.byteslice(@offset, length)
					raise VCDiffError, "Truncated VCDIFF section" if value.nil? || value.bytesize != length
					@offset += length
					value
				end
				
				def readbyte
					self.read(1).ord
				end
			end
		end
	end
	end
