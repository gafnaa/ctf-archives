<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DevSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public $admin;
    public function __construct($admin)
    {
        $this->admin = $admin;
        $this->run();
    }

    public function run(): void
    {
        $admin = $this->admin;
        \App\Models\BlogTags::insert([
            [
                'title' => 'HTML',
                'slug' => 'html',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Tips & Trick',
                'slug' => 'tips-trick',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Tutorial',
                'slug' => 'tutorial',
                'created_at' => now(),
                'updated_at' => now()
            ]
        ]);


        \App\Models\Blog::insert([
            [
                'title' => 'Lorem ipsum dolor sit amet',
                'slug' => 'lorem-ipsum-dolor-sit-amet',
                'image' => 'blogs/1.png',
                'content' => 'lorem',
                'author' => $admin->id,
                'tags' => json_encode(array(1, 2)),
                'is_published' => true,
                'meta_description' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex!',
                'created_at' => '2021-04-16 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'Lorem ipsum dolor sit amet 2',
                'slug' => 'lorem-ipsum-dolor-sit-amet-2',
                'image' => 'blogs/2.png',
                'content' => 'lorem',
                'author' => $admin->id,
                'tags' => json_encode(array(3, 2)),
                'is_published' => true,
                'meta_description' => 'Lorem ipsum dolor sit,sd asd asd awd awda wdaw awdawd amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex!',
                'created_at' => '2021-04-16 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'Autentikasi dengan Laravel Sanctum & Fortify untuk SPA',
                'slug' => 'autentikasi-dengan-laravel-sanctum-fortify-untuk-spa',
                'image' => 'blogs/3.png',
                'content' => 'Nah jetstream sendiri juga menggunakan fortify sebagai api auth nya, namun, jika kita tidak ingin menggunakan jetstream melainkan ingin memakai fortify nya saja juga bisa, terlebih lagi, kita bisa turn off view nya yang by default bisa kita tentukan dalam AppServiceProvider, kali ini saya akan menganggap bahwa Anda ingin memakai fortify sebagai api saja, dan untuk view auth nya menggunakan spa yang telah Anda punya.',
                'author' => $admin->id,
                'tags' => json_encode(array(3, 1)),
                'is_published' => true,
                'meta_description' => 'Kita sama - sama tau, begitu banyak first party package untuk melakukan autentikasi, seperti breeze, ui, jetstream.',
                'created_at' => '2021-04-15 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'Membangun Forum Dengan Laravel TDD Sudah Selesai',
                'slug' => 'membangun-forum-dengan-laravel-tdd-sudah-selesai',
                'image' => 'blogs/4.png',
                'content' => 'Nah jetstream sendiri juga menggunakan fortify sebagai api auth nya, namun, jika kita tidak ingin menggunakan jetstream melainkan ingin memakai fortify nya saja juga bisa, terlebih lagi, kita bisa turn off view nya yang by default bisa kita tentukan dalam AppServiceProvider, kali ini saya akan menganggap bahwa Anda ingin memakai fortify sebagai api saja, dan untuk view auth nya menggunakan spa yang telah Anda punya.',
                'author' => $admin->id,
                'tags' => json_encode(array(3, 1, 2)),
                'is_published' => true,
                'meta_description' => 'Seperti yang kita sama-sama ketahui, pada seri ini kita akan membangun forum dengan test driven development, yang mana kita akan mengimplementasikan Pest dari pada PHPUnit, kita juga akan menggunakan Inertiajs disertai dengan Tailwind CSS.',
                'created_at' => '2021-02-15 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'Perbedaan ForEach dan Map Dalam Javascript',
                'slug' => 'perbedaan-foreach-dan-map-dalam-javascript',
                'image' => 'blogs/5.png',
                'content' => 'Jika Anda sering bermain dengan JavaScript akhir - akhir ini, Anda mungkin menemukan dua metode Array yang sepertinya fungsi dari kedua itu sama.',
                'author' => $admin->id,
                'tags' => json_encode(array(3, 2)),
                'is_published' => true,
                'meta_description' => 'Jika Anda sering bermain dengan JavaScript akhir - akhir ini, Anda mungkin menemukan dua metode Array yang sepertinya fungsi dari kedua itu sama.',
                'created_at' => '2021-01-21 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'Inertia.js Sekarang Sudah Versi 1.0',
                'slug' => 'inertiajs-sekarang-sudah-versi-1-0',
                'image' => 'blogs/8.png',
                'content' => 'Tepat pada tanggal 14 januari, Inertia.js telah resmi rilis versi 1.0, yang mana pada rilis kali ini semua di buat lebih singkat. Lebih singkat dalam arti tidak terpisah-pisah lagi.',
                'author' => $admin->id,
                'tags' => json_encode(array(2)),
                'is_published' => true,
                'meta_description' => 'Tepat pada tanggal 14 januari, Inertia.js telah resmi rilis versi 1.0, yang mana pada rilis kali ini semua di buat lebih singkat. Lebih singkat dalam arti tidak terpisah-pisah lagi.',
                'created_at' => '2021-01-20 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'PHP dan Laravel Fixer Dengan Duster',
                'slug' => 'php-dan-laravel-fixer-dengan-duster',
                'image' => 'blogs/7.png',
                'content' => 'Tepat pada tanggal 14 januari, Inertia.js telah resmi rilis versi 1.0, yang mana pada rilis kali ini semua di buat lebih singkat. Lebih singkat dalam arti tidak terpisah-pisah lagi.',
                'author' => $admin->id,
                'tags' => json_encode(array(1)),
                'is_published' => true,
                'meta_description' => 'Dalam artikel ini kita akan membahas tentang PHP dan Laravel fixer yang baru saja di rilis oleh tim tighten yaitu Duster.',
                'created_at' => '2021-01-15 00:00:00',
                'updated_at' => now()
            ],
            [
                'title' => 'Intro to Hellayan.com',
                'slug' => 'intro-to-hellayan-com',
                'image' => 'blogs/6.png',
                'content' => 'Hellayan adalah platform kursus yang mana setiap hal akan di ajarkan dari tulisan seperti layaknya buku, namun ini hanya online.',
                'author' => $admin->id,
                'tags' => json_encode(array(2,3)),
                'is_published' => true,
                'meta_description' => 'Hellayan adalah platform kursus yang mana setiap hal akan di ajarkan dari tulisan seperti layaknya buku, namun ini hanya online.',
                'created_at' => now(),
                'updated_at' => now()
            ]
        ]);

        for($i=0; $i <=10; $i++) {
            // random number range
            $rand = rand(1, 8);
            // random slug
            $random = substr(md5(mt_rand()), 0, 7);
            $created_At = now()->subDays($i);
            \App\Models\Blog::insert([
                'title' => 'Lorem ipsum dolor sit amet '.$i,
                'slug' => 'lorem-'.$random,
                'image' => 'blogs/'.$rand.'.png',
                'content' => 'lorem',
                'author' => $admin->id,
                'tags' => json_encode(array(1, 2)),
                'is_published' => true,
                'meta_description' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex!',
                'created_at' => $created_At,
                'updated_at' => now()
            ]);
        }


        \App\Models\ProductTags::insert([
            [
                'title' => 'HTML',
                'slug' => 'html',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'PHP',
                'slug' => 'php',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'React',
                'slug' => 'react',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'NodeJs',
                'slug' => 'nodejs',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Landing',
                'slug' => 'landing',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'UI Template',
                'slug' => 'ui',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Wordpress',
                'slug' => 'wordpress',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Javascript',
                'slug' => 'js',
                'created_at' => now(),
                'updated_at' => now()
            ]
        ]);

        for($i=0; $i <=20; $i++) {
            // random number range
            $rand = rand(1, 8);
            // random slug
            $random = substr(md5(mt_rand()), 0, 7);
            $created_At = now()->subDays($i);
            \App\Models\Product::insert([
                'title' => 'Lorem ipsum dolor sit amet '.$i,
                'slug' => $random,
                'image' => 'item/'.$rand.'.png',
                'content' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex! asdas daw awaw dgnawydgayw duayw yauwgduy agudawd awd awd awd awdawd',
                'author' => $admin->id,
                'tags' => json_encode(array(rand(1,3), rand(4,8))),
                'is_published' => true,
                'price' => json_encode(array(
                    'usd' => rand(10, 100),
                    'idr' => rand(100000, 1000000)
                )),
                'preview' => 'https://www.youtube.com?id='.$i,
                'meta_description' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas.',
                'release' => json_encode(
                    array(
                        'latest' => '1.0.'.$i,
                        'latest_url'=> 'http://google.com?id='.$i,
                        'archive' => array(
                            array(
                                'version' => '1.0.0',
                                'url' => 'http://google.com',
                            ),
                            array(
                                'version' => '1.0.'.$i,
                                'url' => 'http://google.com?id='.$i,
                            ),
                        )
                    )
                ),
                'created_at' => $created_At,
                'updated_at' => now()
            ]);
        }

        \App\Models\OwnedLicense::create([
            'user_id' => $admin->id,
            'license_key' => 'PRODUCT-XXWW-DSW2-FF42-34DD',
            'item' => 'digital-product',
            'item_id' => \App\Models\Product::first()->id,
            'expires_at' => now()->addDays(30)
        ]);

        \App\Models\OwnedLicense::create([
            'user_id' => $admin->id,
            'license_key' => 'PRODUCT-WSL3-2311-XF42-34SD',
            'item' => 'digital-product',
            'item_id' => \App\Models\Product::find(2)->id,
        ]);

        \App\Models\License::create([
            'license_key' => 'PRODUCT-SW2W-DSW2-T3W2-2G3D',
            'item' => 'digital-product',
            'item_id' => \App\Models\Product::find(3)->id,
        ]);

        \App\Models\License::create([
            'license_key' => 'PRODUCT-2222-FS22-FWWS-3123',
            'item' => 'digital-product',
            'item_id' => \App\Models\Product::find(2)->id,
        ]);

        \App\Models\ApihubTags::insert([
            [
                'title' => 'Media Social',
                'slug' => 'media-social',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Downloader',
                'slug' => 'downloader',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Scrape',
                'slug' => 'scrape',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Anime',
                'slug' => 'anime',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Tools',
                'slug' => 'tools',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Game',
                'slug' => 'game',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Random',
                'slug' => 'random',
                'created_at' => now(),
                'updated_at' => now()
            ],
            [
                'title' => 'Other',
                'slug' => 'other',
                'created_at' => now(),
                'updated_at' => now()
            ],
        ]);

        for($i=0; $i <=20; $i++) {
            // random number range
            $rand = rand(1, 4);
            // random slug
            $random = substr(md5(mt_rand()), 0, 7);
            $created_At = now()->subDays($i);
            \App\Models\Apihub::insert([
                'title' => 'Google Scrape v'.$i,
                'slug' => $random,
                'image' => 'apis/'.$rand.'.png',
                'author' => $admin->id,
                'tags' => json_encode(array(1, 2)),
                'is_published' => true,
                'meta_description' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex!',
                'created_at' => $created_At,
                'updated_at' => now()
            ]);
        }

        $mapih = \App\Models\Apihub::create([
            'title' => 'Mediafire Scrape',
            'slug' => substr(md5(mt_rand()), 0, 7),
            'image' => 'apis/1.png',
            'author' => $admin->id,
            'tags' => json_encode(array(1, 5, 3)),
            'is_published' => true,
            'meta_description' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex!',
            'readme' => 'Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex! Lorem ipsum dolor sit, amet consectetur adipisicing elit. Rem libero possimus illo sit voluptas ex!',
        ]);

        // make endpoint

        \App\Models\ApihubEndpoint::create([
            'apihub_id' => $mapih->id,
            'title' => 'Using GET',
            'url' => 'http://localhost:3000/mediafire?url=<url>&apikey=<apikey>',
            'method' => 'GET',
            'data' => null,
            'response' => json_encode(array(
                "status"=> true,
                "message"=> "success get data",
                "data"=>array(
                    "title"=> "Filename.ext",
                    "size" => "size files",
                    "link"=>"https://download1507.mediafire.com/xj320qih9nvlno0/file.ext"
                )
            )),
        ]);

        \App\Models\ApihubEndpoint::create([
            'apihub_id' => $mapih->id,
            'title' => 'Using POST',
            'url' => 'http://localhost:3000/mediafire',
            'method' => 'POST',
            'data' => json_encode(array(
                'apikey' => '{apikey}',
                'url' => 'https://www.mediafire.com/file/xj320qih9nvlno0/dokumen_rahasia.pdf/file'
            )),
            'response' => json_encode(array(
                "status"=> true,
                "message"=> "success get data",
                "data"=>array(
                    "title"=> "Filename.ext",
                    "size" => "size files",
                    "link"=>"https://download1507.mediafire.com/xj320qih9nvlno0/file.ext"
                )
            )),
        ]);
        \App\Models\UserTransaction::create([
            'user_id' => $admin->id,
            'type' => 'earnings',
            'amount' => 45000,
            'description' => 'Referral Earnings',
            'status' => 'approved',
        ]);
        \App\Models\UserTransaction::create([
            'user_id' => $admin->id,
            'type' => 'earnings',
            'amount' => 50000,
            'description' => 'Referral Earnings',
            'status' => 'approved',
        ]);
        \App\Models\UserTransaction::create([
            'user_id' => $admin->id,
            'type' => 'withdraw',
            'amount' => 50000,
            'method' => 'DANA',
            'to' => '085745876650',
            'description' => 'Withdrawal Amount',
            'status' => 'approved',
        ]);
        \App\Models\UserTransaction::create([
            'user_id' => $admin->id,
            'type' => 'withdraw',
            'amount' => 20000,
            'description' => 'Withdrawal Amount',
            'method' => 'DANA',
            'to' => '085745876650',
            'status' => 'rejected',
            'message_status' => 'Saldo tidak mencukupi',
        ]);
    }
}
