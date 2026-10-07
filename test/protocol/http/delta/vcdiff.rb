# frozen_string_literal: true

require "protocol/http/delta/vcdiff"

describe Protocol::HTTP::Delta::VCDiff do
	let(:vcdiff) {Protocol::HTTP::Delta::VCDiff}
	
	describe ".encode/.decode" do
		[
			["", ""],
			["", "hello"],
			["hello", ""],
			["hello world", "hello world"],
			["hello world", "hello brave new world"],
			["abcdefgh", "xyzabcdefgh123"],
			["abc", "abcabcabc"],
			["", "abcabcabc"],
			["a" * 100, "a" * 100 + "b"],
			["The quick brown fox. " * 20, "The quick brown fox. " * 10 + "jumped! " + "The quick brown fox. " * 9],
		].each_with_index do |(source, target), index|
			it "round-trips case #{index}" do
				delta = vcdiff.encode(source, target)
				
				expect(vcdiff.decode(source, delta)).to be == target
			end
		end
		
		it "produces a well-formed header" do
			delta = vcdiff.encode("hello", "hello world")
			
			# Magic bytes, version 0 and no secondary compression or custom code
			# table:
			expect(delta.byteslice(0, 4)).to be == "\xD6\xC3\xC4\x00".b
			expect(delta.getbyte(4)).to be == 0
			expect(delta.getbyte(5)).to be == 0
		end
		
		it "produces smaller deltas for similar instances" do
			source = "The quick brown fox. " * 20
			target = "The quick brown fox. " * 10 + "jumped! " + "The quick brown fox. " * 9
			
			delta = vcdiff.encode(source, target)
			
			expect(delta.bytesize).to be < target.bytesize
		end
		
		it "encodes copies within the target window" do
			# With an empty source, repeated data can only be copied from the
			# target window itself:
			target = "abc" * 100
			delta = vcdiff.encode("", target)
			
			expect(delta.bytesize).to be < target.bytesize
			expect(vcdiff.decode("", delta)).to be == target
		end
	end
	
	describe "code table" do
		let(:code_table) {vcdiff::CODE_TABLE}
		
		it "has 256 entries" do
			expect(code_table.size).to be == 256
		end
		
		it "has RUN at opcode 0" do
			expect(code_table[0]).to be == [vcdiff::RUN, 0, 0, vcdiff::NOOP, 0, 0]
		end
		
		it "has ADD at opcodes 1-17" do
			expect(code_table[1]).to be == [vcdiff::ADD, 0, 0, vcdiff::NOOP, 0, 0]
			expect(code_table[2]).to be == [vcdiff::ADD, 1, 0, vcdiff::NOOP, 0, 0]
			expect(code_table[17]).to be == [vcdiff::ADD, 16, 0, vcdiff::NOOP, 0, 0]
		end
		
		it "has COPY at opcodes 18-170" do
			expect(code_table[18]).to be == [vcdiff::COPY, 0, 0, vcdiff::NOOP, 0, 0]
			expect(code_table[34]).to be == [vcdiff::COPY, 16, 0, vcdiff::NOOP, 0, 0]
			expect(code_table[35]).to be == [vcdiff::COPY, 0, 1, vcdiff::NOOP, 0, 0]
			expect(code_table[170]).to be == [vcdiff::COPY, 16, 8, vcdiff::NOOP, 0, 0]
		end
		
		it "has combined ADD+COPY at opcodes 171-255" do
			expect(code_table[171]).to be == [vcdiff::ADD, 1, 0, vcdiff::COPY, 4, 0]
			expect(code_table[206]).to be == [vcdiff::ADD, 4, 0, vcdiff::COPY, 4, 8]
			expect(code_table[255]).to be == [vcdiff::ADD, 1, 0, vcdiff::COPY, 8, 6]
		end
	end
	
	describe "fixtures" do
		def fixture_path(name)
			File.expand_path(File.join("fixtures", name), __dir__)
		end
		
		it "decodes a COPY within the target window" do
			# Hand-crafted delta: COPY 3 bytes from the source window, then COPY
			# 6 bytes from the target window itself (VCD_HERE, overlapping):
			delta = File.read(fixture_path("target_window_copy.vcdiff"))
			
			expect(vcdiff.decode("abc", delta)).to be == "abcabcabc"
		end
		
		it "decodes RUN and ADD instructions without a source window" do
			delta = File.read(fixture_path("run_and_add.vcdiff"))
			
			expect(vcdiff.decode("", delta)).to be == "aaab"
		end
		
		it "decodes a combined ADD+COPY opcode" do
			delta = File.read(fixture_path("combined_add_copy.vcdiff"))
			
			expect(vcdiff.decode("wxyz", delta)).to be == "awxyz"
		end
	end
	
	describe "errors" do
		let(:delta) {vcdiff.encode("hello world", "hello brave new world")}
		
		it "rejects a truncated delta" do
			expect do
				vcdiff.decode("hello world", delta.byteslice(0, 10))
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /Truncated|extends past/)
		end
		
		it "rejects invalid magic bytes" do
			modified = delta.dup
			modified.setbyte(0, 0)
			
			expect do
				vcdiff.decode("hello world", modified)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /magic/)
		end
		
		it "rejects an unsupported version" do
			modified = delta.dup
			modified.setbyte(4, 1)
			
			expect do
				vcdiff.decode("hello world", modified)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /version/)
		end
		
		it "rejects secondary compression" do
			modified = delta.dup
			modified.setbyte(5, vcdiff::VCD_DECOMPRESS)
			
			expect do
				vcdiff.decode("hello world", modified)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /[Ss]econdary compression/)
		end
		
		it "rejects custom code tables" do
			modified = delta.dup
			modified.setbyte(5, vcdiff::VCD_CODETABLE)
			
			expect do
				vcdiff.decode("hello world", modified)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /[Cc]ode table/)
		end
		
		it "rejects target windows as source" do
			delta = vcdiff.encode("", "hello")
			delta.setbyte(6, vcdiff::VCD_TARGET)
			
			expect do
				vcdiff.decode("", delta)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /VCD_TARGET/)
		end
		
		it "rejects a mismatched base" do
			expect do
				vcdiff.decode("goodbye world", delta)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /Source window mismatch/)
			
			expect do
				vcdiff.decode("", delta)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /Source window mismatch/)
		end
		
		it "rejects a delta without a source window when a base is provided" do
			delta = vcdiff.encode("", "hello")
			
			expect do
				vcdiff.decode("hello", delta)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /does not reference/)
		end
		
		it "rejects COPY addresses out of range" do
			modified = vcdiff.encode("abcd", "abcd")
			
			# Corrupt the address of the COPY instruction (the last byte of the
			# delta) to point past the end of the unified window:
			modified.setbyte(modified.bytesize - 1, 100)
			
			expect do
				vcdiff.decode("abcd", modified)
			end.to raise_exception(Protocol::HTTP::Delta::Error, message: be =~ /out of range/)
		end
	end
end
