<?php

// configurasi referral by velixs.com - ilsya.my.id
$section = [
    [
        "amount" => 20000,
        "withdraw" => 20000
    ],
    [
        "amount" => 50000,
        "withdraw" => 50000
    ],
    [
        "amount" => 100000,
        "withdraw" => 100000
    ],
    [
        "amount" => 150000,
        "withdraw" => 150000
    ],
    [
        "amount" => 200000,
        "withdraw" => 200000
    ],
    [
        "amount" => 500000,
        "withdraw" => 500000
    ],
];
return [
    "config" => [
        "cookie_name" => "referral",
        "expired" => 30, // day
        "commission" => 0.15
    ],
    "payment" => [
        [
            "name" => "DANA",
            "status" => true,
            "currency" => "Rp",
            "placeholder" => "Phone number:0812xxxxxxxx",
            "section" => $section
        ],
        [
            "name" => "GOPAY",
            "status" => true,
            "currency" => "Rp",
            "placeholder" => "Phone number:0812xxxxxxxx",
            "section" => $section
        ],
        [
            "name" => "OVO",
            "status" => true,
            "currency" => "Rp",
            "placeholder" => "Phone number:0812xxxxxxxx",
            "section" => $section
        ],
        [
            "name" => "PayPal",
            "status" => true,
            "currency" => "$",
            "placeholder" => "Paypal email:example@gmail.com",
            "section" => [
                [
                    "amount" => 67500,
                    "withdraw" => 5
                ],
                [
                    "amount" => 100000,
                    "withdraw" => 7.41
                ],
                [
                    "amount" => 150000,
                    "withdraw" => 11.11
                ],
                [
                    "amount" => 200000,
                    "withdraw" => 14.81
                ],
                [
                    "amount" => 300000,
                    "withdraw" => 22.22
                ],
            ]
        ]
    ]
];
