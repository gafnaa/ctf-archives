<?php

namespace App\Http\Controllers\Admin;

use App\Helpers\Layouts;
use App\Http\Controllers\Controller;
use App\Models\Blog;
use App\Models\OwnedLicense;
use App\Models\Product;
use App\Models\User;
use App\Models\Visitor;
use Carbon\Carbon;
use Illuminate\Http\Request;

class MainController extends Controller
{
    public function index(){
        $data['count_product'] = $this->formatShort(Product::count());
        $data['count_blog'] = $this->formatShort(Blog::count());
        $data['count_purchases'] = $this->formatShort(OwnedLicense::count());
        $data['count_users'] = $this->formatShort(User::count());
        $data['browsers'] = Visitor::countBrowser();
        $counterys = [];
        foreach(Visitor::countCountry() as $countery){
            $counterys['name'][] = $countery->country;
            $counterys['total'][] = $countery->total;
            $counterys['percentage'][] = $countery->percentage;
        }

        $visitorMonth = [];
        $visitorMonth['display'] = [
            'current' => Carbon::now()->format('M'),
            'old' => Carbon::now()->subMonth()->format('M'),
        ];
        for ($i = 1; $i <= Carbon::now()->daysInMonth; $i++) {
            $visitorMonth['month'][] = Carbon::now()->format('M ' . $i);
            $visitorMonth['total'][] = Visitor::whereDate('created_at', Carbon::now()->format('Y-m-' . $i))->count();
        }
        $data['month'] = $visitorMonth;
        $data['counterys'] = $counterys;

        $data['page_views'] = Visitor::countPageView()->map(function ($item, $key) {
            $item->total = $this->formatShort($item->total);
            return $item;
        });
        return Layouts::view('admin.main.index',$data);
    }

    function formatShort($number){
        $number = (int) $number;
        if($number < 1000){
            return $number;
        }else if($number < 1000000){
            return round($number/1000,1).'K';
        }else if($number < 1000000000){
            return round($number/1000000,1).'M';
        }else if($number < 1000000000000){
            return round($number/1000000000,1).'B';
        }else{
            return round($number/1000000000000,1).'T';
        }
    }
}
