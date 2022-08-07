limit = false

targetInfo = gg.getTargetInfo()
app = targetInfo.packageName

function rwmem(Address, SizeOrBuffer)
	assert(Address ~= nil, "[rwmem]: error, provided address is nil.")
	_rw = {}
	if type(SizeOrBuffer) == "number" then
		_ = ""
		for _ = 1, SizeOrBuffer do _rw[_] = {address = (Address - 1) + _, flags = gg.TYPE_BYTE} end
		for v, __ in ipairs(gg.getValues(_rw)) do
		  if __.value == 00 and limit == true then
		    return _
		  end
		  _ = _ .. string.format("%02X", __.value & 0xFF)
		  -- payload = payload .. string.char(__.value)
        end
		return _
	end
	Byte = {} SizeOrBuffer:gsub("..", function(x) 
		Byte[#Byte + 1] = x _rw[#Byte] = {address = (Address - 1) + #Byte, flags = gg.TYPE_BYTE, value = x .. "h"} 
	end)
	gg.setValues(_rw)
end

function hexdecode(hex)
   return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end

function hexencode(str)
   return (str:gsub(".", function(char) return string.format("%2x", char:byte()) end))
end

function Dec2Hex(nValue)
	nHexVal = string.format("%X", nValue);
	sHexVal = nHexVal.."";
	return sHexVal;
end

function ToInteger(number)
    return math.floor(tonumber(number) or error("Could not cast '" .. tostring(number) .. "' to number.'"))
end

function save(data)
    io.open(gg.EXT_STORAGE .. "/decrypt.txt", "w"):write(hexdecode(data))
    gg.toast("✅ Successfully!")
end

function HttpInjector()
    limit = true
    gg.clearResults()
    gg.setVisible(false)
    gg.setRanges(gg.REGION_C_ALLOC)
    gg.searchNumber("h7B22636F6E66696745787069727954696D657374", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
    local r = gg.getResults(1)
    if #r < 1 then
        print("⚠ No file found in memory.")
        os.exit()
    end
    gg.searchNumber("h7B", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
    local r = gg.getResults(1000)
    readedMem = rwmem(r[1].address, 50000)
    save(readedMem)
    gg.clearResults()
end

function HTTPCustom()

    gg.clearResults()
    gg.setRanges(gg.REGION_JAVA_HEAP)
    gg.setVisible(false)
    
    -- SSH, Payload
    gg.searchNumber("h 3A 34 34 33 40", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
    local r = gg.getResults(1)
    if #r < 1 then
        gg.toast("⚠ Method 1 failed")
        hc_method2 = true
    end
    
    if hc_method2 then
        gg.searchNumber("h 55 70 67 72 61 64 65 3A", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
        local r = gg.getResults(1)
        if #r < 1 then
            gg.toast("⚠ Method 2 failed")
            hc_method3 = true
        end
    end
    
    if hc_method3 then
        gg.searchNumber("h 3A 38 30 40", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
        local r = gg.getResults(1)
        if #r < 1 then
            gg.toast("⚠ Method 3 failed")
            hc_method4 = true
        end
    end
    
    -- V2ray
    if hc_method4 then
        limit = true
        gg.searchNumber("h 7B 0A 09 09 22 69 6E 62 6F 75 6E 64", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
        local r = gg.getResults(1)
        if #r < 1 then
            gg.toast("⚠ Method 4 failed")
            hc_method6 = true
        end
    end
    
    if hc_method6 then
        print("❌ All methods failed")
        os.exit()
    end
    
    local r = gg.getResults(1000)
    if limit == false then
        r[1].address = r[1].address - 0x2000
    end
    
    readedMem = rwmem(r[1].address, 50000)
    save(readedMem)
    gg.clearResults()
    
end

if app == "com.evozi.injector" then HttpInjector()
elseif app == "com.evozi.injector.lite" then HttpInjector()
elseif app == "xyz.easypro.httpcustom" then HTTPCustom()
else
gg.toast("⚠ Decrypt app not found.")
end

gg.clearResults()
os.exit()