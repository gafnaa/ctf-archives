<?php
require_once 'Library.php';
require_once 'Book.php';
require_once 'Member.php';
require_once 'Loan.php';

if (isset($_COOKIE['library_data'])) {
    $data = base64_decode($_COOKIE['library_data']);
    unserialize($data);

} else {
    $default = new Loan();
    setcookie('library_data', base64_encode(serialize($default)));
    header("Location: ".$_SERVER['REQUEST_URI']);
    exit();
}
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raya Lucaria Academy - The Premier Institute of Glintstone Sorcery</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
	    font-family: Arial, sans-serif;
        }
        
        body {
            background-color: #0a0a1a;
            color: #e0e0ff;
            line-height: 1.6;
        }
        
        header {
            background: linear-gradient(rgba(0, 0, 20, 0.8), rgba(0, 0, 40, 0.8)), 
                        url('https://static0.gamerantimages.com/wordpress/wp-content/uploads/2022/03/elden-ring-academy.jpg');
            background-size: cover;
            background-position: center;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 0 20px;
            position: relative;
        }
        
        .header-content {
            max-width: 800px;
            z-index: 2;
        }
        
        h1 {
            font-size: 3.5rem;
            margin-bottom: 20px;
            color: #c0a0ff;
            text-shadow: 0 0 10px rgba(192, 160, 255, 0.5);
        }
        
        .tagline {
            font-size: 1.5rem;
            margin-bottom: 30px;
            color: #a0c0ff;
        }
        
        nav {
            background-color: rgba(10, 5, 30, 0.9);
            padding: 15px 0;
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 1px solid #303050;
        }
        
        nav ul {
            display: flex;
            justify-content: center;
            list-style: none;
            flex-wrap: wrap;
        }
        
        nav ul li {
            margin: 0 20px;
        }
        
        nav ul li a {
            color: #c0a0ff;
            text-decoration: none;
            font-size: 1.1rem;
            transition: color 0.3s, text-shadow 0.3s;
        }
        
        nav ul li a:hover {
            color: #ffffff;
            text-shadow: 0 0 8px #a0c0ff;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        h2 {
            font-size: 2.5rem;
            margin-bottom: 30px;
            color: #c0a0ff;
            text-align: center;
            border-bottom: 2px solid #303050;
            padding-bottom: 10px;
        }
        
        .section {
            margin-bottom: 60px;
        }
        
        .magic-animation {
            text-align: center;
            margin: 40px 0;
        }
        
        .magic-animation img {
            max-width: 100%;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(192, 160, 255, 0.3);
            border: 1px solid #505070;
        }
        
        .two-column {
            display: flex;
            flex-wrap: wrap;
            gap: 30px;
            margin: 40px 0;
        }
        
        .column {
            flex: 1;
            min-width: 300px;
        }
        
        .column img {
            width: 100%;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 0 15px rgba(192, 160, 255, 0.2);
        }
        
        h3 {
            font-size: 1.8rem;
            margin: 20px 0;
            color: #a0c0ff;
        }
        
        p {
            margin-bottom: 20px;
            font-size: 1.1rem;
        }
        
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #6a3093, #a044ff);
            color: white;
            padding: 12px 25px;
            border-radius: 30px;
            text-decoration: none;
            font-weight: bold;
            margin-top: 20px;
            border: none;
            cursor: pointer;
            transition: transform 0.3s, box-shadow 0.3s;
            box-shadow: 0 0 15px rgba(106, 48, 147, 0.5);
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 0 25px rgba(106, 48, 147, 0.8);
        }
        
        footer {
            background-color: #0a0510;
            padding: 30px 0;
            text-align: center;
            border-top: 1px solid #303050;
        }
        
        .footer-content {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .social-links {
            margin: 20px 0;
        }
        
        .social-links a {
            color: #c0a0ff;
            margin: 0 15px;
            font-size: 1.5rem;
            transition: color 0.3s;
        }
        
        .social-links a:hover {
            color: #ffffff;
        }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <h1>Raya Lucaria Academy</h1>
            <p class="tagline">The Premier Institute of Glintstone Sorcery</p>
            <a href="#admissions" class="btn">Begin Your Arcane Journey</a>
        </div>
    </header>
    
    <nav>
        <ul>
            <li><a href="#about">About the Academy</a></li>
            <li><a href="#curriculum">Curriculum</a></li>
            <li><a href="#faculty">Faculty</a></li>
            <li><a href="#campus">Campus</a></li>
            <li><a href="#admissions">Admissions</a></li>
        </ul>
    </nav>
    
    <div class="container">
        <section id="about" class="section">
            <h2>About Raya Lucaria Academy</h2>
            
            <div class="magic-animation">
                <img src="https://44.media.tumblr.com/ac1ca6f080199423c1b9ae5b5492564f/1dc6af422ed454cc-40/s540x810_f1/7f0ff68bdba35e98ab10c51021b7626887fb0470.gif" alt="Glintstone Sorcery">
            </div>
            
            <div class="two-column">
                <div class="column">
                    <h3>Our Legacy</h3>
                    <p>Founded in the age of the Erdtree, Raya Lucaria Academy has stood as the pinnacle of glintstone sorcery for centuries. Our halls have trained the most accomplished sorcerers in the Lands Between, preserving and advancing the sacred art of magic.</p>
                    <p>The Academy's towering spires and grand libraries house knowledge accumulated over generations, from the most fundamental incantations to the most advanced primeval sorceries.</p>
                </div>
                <div class="column">
                    <h3>Our Mission</h3>
                    <p>To cultivate the next generation of sorcerers through rigorous study of glintstone sorcery, fostering both technical mastery and creative application of magical principles.</p>
                    <p>We maintain the sacred traditions of our founders while pushing the boundaries of magical knowledge through continuous research and discovery.</p>
                    <a href="#curriculum" class="btn">Explore Our Curriculum</a>
                </div>
            </div>
        </section>
        
        <section id="campus" class="section">
            <h2>Our Hallowed Grounds</h2>
            
            <div class="two-column">
                <div class="column">
                    <img src="https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/f/b828ee08-d620-4fc8-9915-2b4b715e521d/df8702u-a2e7ac3d-196b-4ef7-b9ad-f5ff780ed710.jpg/v1/fill/w_1192,h_670,q_70,strp/grand_library__raya_lucaria_by_tntiseverywere_df8702u-pre.jpg?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1cm46YXBwOjdlMGQxODg5ODIyNjQzNzNhNWYwZDQxNWVhMGQyNmUwIiwiaXNzIjoidXJuOmFwcDo3ZTBkMTg4OTgyMjY0MzczYTVmMGQ0MTVlYTBkMjZlMCIsIm9iaiI6W1t7ImhlaWdodCI6Ijw9MTA4MCIsInBhdGgiOiJcL2ZcL2I4MjhlZTA4LWQ2MjAtNGZjOC05OTE1LTJiNGI3MTVlNTIxZFwvZGY4NzAydS1hMmU3YWMzZC0xOTZiLTRlZjctYjlhZC1mNWZmNzgwZWQ3MTAuanBnIiwid2lkdGgiOiI8PTE5MjAifV1dLCJhdWQiOlsidXJuOnNlcnZpY2U6aW1hZ2Uub3BlcmF0aW9ucyJdfQ.uFRDZT6vOsGt64gphszeF3k_2jKSHsGBXRsDTjEPquQ" alt="Grand Library of Raya Lucaria" alt="Grand Library of Raya Lucaria">
                </div>
                <div class="column">
                    <h3>The Grand Library</h3>
                    <p>The heart of our Academy, this magnificent repository contains countless tomes of magical knowledge, from ancient scrolls to contemporary treatises on advanced sorcery.</p>
                    <p>Students may access the lower levels upon enrollment, with higher clearance granted as they progress in their studies. The uppermost chambers are reserved for the most accomplished scholars and faculty members.</p>
                    <h3>Other Notable Locations</h3>
                    <p>• The Debate Parlor - Where students demonstrate their mastery through magical duels</p>
                    <p>• The Glintstone Gardens - Where rare magical flora is cultivated</p>
                    <p>• The Moon Observatory - For celestial studies and communion</p>
                </div>
            </div>
        </section>
        
        <section id="admissions" class="section">
            <h2>Join Our Ranks</h2>
            <div class="two-column">
                <div class="column">
                    <h3>Admission Requirements</h3>
                    <p>Prospective students must demonstrate:</p>
                    <p>• Basic proficiency in fundamental sorceries</p>
                    <p>• A keen intellect and capacity for study</p>
                    <p>• The wisdom to wield magic responsibly</p>
                    <p>• A letter of recommendation from an established sorcerer</p>
                </div>
                <div class="column">
                    <h3>Begin Your Application</h3>
                    <p>The path to magical mastery begins with a single step. Submit your inquiry below to receive our formal application materials.</p>
                    <a href="#" class="btn">Request Application</a>
                </div>
            </div>
        </section>
    </div>
    
    <footer>
        <div class="footer-content">
            <h3>Raya Lucaria Academy</h3>
            <p>Liurnia of the Lakes, The Lands Between</p>
            <div class="social-links">
                <a href="#">✉</a>
                <a href="#">📜</a>
                <a href="#">🔮</a>
            </div>
            <p>© 2025 oreosec. All magical rights reserved.</p>
        </div>
    </footer>
</body>
</html>
