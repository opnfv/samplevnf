--
-- Copyright (c) 2020 Intel Corporation
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

function convertIPToHex(ip)
  local address_chunks = {}
  if type(ip) ~= "string" then
    print ("IP ADDRESS ERROR: ", ip)
    return "IP ADDRESS ERROR"
  end

  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)(\/%d+)$")}
  if #chunks == 5 then
    for i,v in ipairs(chunks) do
      if i < 5 then
        if tonumber(v) > 255 then
          print ("IPV4 ADDRESS ERROR: ", ip)
          return "IPV4 ADDRESS ERROR"
        end
        address_chunks[#address_chunks + 1] = string.format ("%02x", v)
      end
    end
    result = table.concat(address_chunks, " ")
    print ("Hex IPV4: ", result)
    return result
  end

  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks == 4 then
    for i,v in ipairs(chunks) do
      if tonumber(v) > 255 then
        print ("IPV4 ADDRESS ERROR: ", ip)
        return "IPV4 ADDRESS ERROR"
      end
      address_chunks[#address_chunks + 1] = string.format ("%02x", v)
    end
    result = table.concat(address_chunks, " ")
    print ("Hex IPV4: ", result)
    return result
  end

  delimiter = ":"
  for match in (ip..delimiter):gmatch("(.-)"..delimiter) do
    if match ~= "" then
      number = tonumber(match, 16)
      if number <= 65535 then
        table.insert(address_chunks, string.format("%02x %02x",number/256,number % 256))
      end
    else
      table.insert(address_chunks, "")
    end
  end
  for i, chunk in ipairs(address_chunks) do
    if chunk =="" then
      table.remove(address_chunks, i)
      for j = 1,(8-#address_chunks) do
        table.insert(address_chunks, i, "00 00")
      end
      break
    end
  end
  result = table.concat(address_chunks, " ")
  print ("Hex IPV6: ", result)
  return result
end
