#!/usr/bin/env python3

x = bytes.fromhex

reqs = [
    [
        {
            'createVerifierRequest': {  # PIN
                'id': x('80'),
                'modeContact': 'always',
                'modeContactless': 'always',
                'minLength': 4,
                'maxLength': 8,
                'retriesContact': 3,
                'retriesContactless': 3
            }
        },
        {
            'createVerifierRequest': {  # PUK
                'id': x('81'),
                'modeContact': 'always',
                'modeContactless': 'always',
                'minLength': 4,
                'maxLength': 8,
                'retriesContact': 3,
                'retriesContactless': 3
            }
        },
        {
            'createObjectRequest': {  # Card Capability Container
                'id': x('5FC107'),
                'modeContact': 'always',
                'modeContactless': 'never',
                'adminKey': x('9B')
            }
        },
        {
            'createObjectRequest': {  # Cardholder Unique Identifier
                'id': x('5FC102'),
                'modeContact': 'always',
                'modeContactless': 'always',
                'adminKey': x('9B')
            }
        },
        {
            'createObjectRequest': {  # X509 Certificate for PIV Authentication
                'id': x('5FC105'),
                'modeContact': 'always',
                'modeContactless': 'never',
                'adminKey': x('9B')
            }
        },
       {
           'createObjectRequest': {  # X509 Certificate for Card Authentication
               'id': x('5FC101'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Cardholder Fingerprints
               'id': x('5FC103'),
               'modeContact': 'pin',
               'modeContactless': 'never',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Cardholder Facial Image
               'id': x('5FC108'),
               'modeContact': 'pin',
               'modeContactless': 'never',
               'adminKey': x('9B')
           }
       },
        {
            'createObjectRequest': {  # Security Object
                'id': x('5FC106'),
                'modeContact': 'always',
                'modeContactless': 'never',
                'adminKey': x('9B')
            }
        },
    ],
   [
       {
           'createObjectRequest': {  # X509 Certificate for Digital Signature
               'id': x('5FC10A'),
               'modeContact': 'always',
               'modeContactless': 'never',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # X509 Certificate for Key Management
               'id': x('5FC10B'),
               'modeContact': 'always',
               'modeContactless': 'never',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Printed Information
               'id': x('5FC122'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Discovery Object
               'id': x('7E'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Key History Object
               'id': x('5FC10C'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 1
               'id': x('5FC10D'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 2
               'id': x('5FC10E'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 3
               'id': x('5FC10F'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 4
               'id': x('5FC110'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 5
               'id': x('5FC111'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 6
               'id': x('5FC112'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 7
               'id': x('5FC113'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
   ],
   [
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 8
               'id': x('5FC114'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 9
               'id': x('5FC115'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 10
               'id': x('5FC116'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 11
               'id': x('5FC117'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 12
               'id': x('5FC118'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 13
               'id': x('5FC119'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 14
               'id': x('5FC11A'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 15
               'id': x('5FC11B'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 16
               'id': x('5FC11C'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 17
               'id': x('5FC11D'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 18
               'id': x('5FC11E'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 19
               'id': x('5FC11F'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       },
       {
           'createObjectRequest': {  # Retired X509 Certificate for Key Management 20
               'id': x('5FC120'),
               'modeContact': 'always',
               'modeContactless': 'always',
               'adminKey': x('9B')
           }
       }
   ]
]
