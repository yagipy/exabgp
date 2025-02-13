#!/usr/bin/env python3

import sys
import os

# ExaBGPのソースディレクトリをパスに追加
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from exabgp.bgp.message.update.nlri.bgpls.nlri import BGPLS
from exabgp.bgp.message.update.nlri.bgpls.link import LINK
from exabgp.bgp.message.update.nlri.bgpls.node import NODE
from exabgp.protocol.family import AFI, SAFI
from exabgp.bgp.message import Action
import json

def decode_bgpls_hex(hex_str):
    try:
        # 16進数文字列をバイトデータに変換
        data = bytes.fromhex(hex_str)
        
        # BGP-LSメッセージをデコード
        nlri, rest = BGPLS.unpack_nlri(AFI.bgpls, SAFI.bgp_ls, data, Action.ANNOUNCE, None)
        
        # 結果を表示
        print("\nDecoded BGP-LS Message:")
        print(f"Type: {nlri.NAME}")
        print(f"Protocol ID: {nlri.proto_id}")
        print(f"Domain: {nlri.domain}")
        
        # JSON形式で整形して表示
        print("\nFormatted JSON:")
        json_data = json.loads(nlri.json())
        print(json.dumps(json_data, indent=2))
        
        return nlri
    
    except Exception as e:
        print(f"Error decoding message: {str(e)}")
        return None

if __name__ == "__main__":
    # サンプルのBGP-LSメッセージ
    sample_hex = "0002FFFF03000000000000000001000020020000040000000102010004C0A87A7E0202000400000000020300040A0A0A0A01010020020000040000000102010004C0A87A7E0202000400000000020300040A020202"
    
    print("Decoding sample BGP-LS message...")
    decode_bgpls_hex(sample_hex)
