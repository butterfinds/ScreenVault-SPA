<?php
session_start();

require_once './vendor/autoload.php'; // Google API client
require_once './mongoDriver/vendor/autoload.php'; // MongoDB client

// Google OAuth Configuration
$clientID = '';
$clientSecret = '';
$redirectUri = 'http://localhost/TOTOONATO/';

$client = new Google\Client();
$client->setClientId($clientID);
$client->setClientSecret($clientSecret);
$client->setRedirectUri($redirectUri);
$client->addScope("email");
$client->addScope("profile");

// MongoDB Connection
$databaseConnection = new MongoDB\Client('mongodb://localhost:27017');
$signUpDb = $databaseConnection->SignUp;

$userCollection = $signUpDb->User;
$userWatchlist = $signUpDb->userWatchlist;

$MovieCollection = $databaseConnection->MovieCollection;
$movieCollection = $MovieCollection->movies;

$SVadmin = $databaseConnection->SVadmin;
$adminCollection = $SVadmin->admin;

$adminEmail = "admin@sv.com";

//GOOGLE OAUTH LOGIN // SIGN UP
if (isset($_GET['code'])) {
  $token = $client->fetchAccessTokenWithAuthCode($_GET['code']);
  if (!isset($token["error"])) {
      $client->setAccessToken($token['access_token']);
      $googleService = new Google\Service\Oauth2($client);
      $googleAccountInfo = $googleService->userinfo->get();

      // Retrieve user info
      $email = $googleAccountInfo->email;
      $username = $googleAccountInfo->name;
      $profilePicture = $googleAccountInfo->picture; // Get profile picture URL

      // Check if user exists in MongoDB
      $existingUser = $userCollection->findOne(['email' => $email]);
      if (!$existingUser) {
          // If not, add new user
          $userCollection->insertOne([
              'email' => $email,
              'username' => $username,
              'profilePicture' => $profilePicture, // Store profile picture URL
              'role' => 'user'
          ]);
          $userWatchlist->insertOne(['email' => $email, 'role' => 'user']);
      } else {
          // Update profile picture in case it changed
          $userCollection->updateOne(
              ['email' => $email],
              ['$set' => ['profilePicture' => $profilePicture]]
          );
      }

      // Set session variables
      $_SESSION['email'] = $email;
      $_SESSION['username'] = $username;
      $_SESSION['profilePicture'] = $profilePicture; // Store profile picture in session
      $_SESSION['role'] = 'user';
      $_SESSION['loggedin'] = true;

      header("Location: index.php");
      exit();
  }
}

// ENCRYPTION KEY
define('ENCRYPTION_KEY', 'BLACKLIVESMATTER'); 

// ENCRYPTION
function encryptPassword($password) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encryptedPassword = openssl_encrypt($password, 'aes-256-cbc', ENCRYPTION_KEY, 0, $iv);
    return base64_encode($encryptedPassword . '::' . $iv);
}

// DECRYPTION
function decryptPassword($encryptedPassword) {
    list($encryptedData, $iv) = explode('::', base64_decode($encryptedPassword), 2);
    return openssl_decrypt($encryptedData, 'aes-256-cbc', ENCRYPTION_KEY, 0, $iv);
}

// SIGN UP FUNCTION
if (isset($_POST['signupEmail']) && isset($_POST['signupPassword']) && isset($_FILES['profilePicture'])) {
    $email = $_POST['signupEmail'];
    $username = $_POST['signupUsername'];
    $password = $_POST['signupPassword'];
    $fullname = $_POST['signupFname'];

    // PASSWORD VALIDATION
    if (!preg_match('/^(?=.*[A-Z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/', $password)) { 
     $_SESSION['signupData'] = $_POST;
     echo "<script> alert('Password should be at least 8 characters long and contain at least one uppercase letter and one special character.'); 
     window.location.href = 'index.php'; </script>";
     exit(); 
    }

    // ENCRYPT PASSWORD
    $encryptedPassword = encryptPassword($password);

    // PROCESSING THE FILE
    $profilePicture = file_get_contents($_FILES['profilePicture']['tmp_name']);
    $fileType = $_FILES['profilePicture']['type'];

    // ADD USER TO DATABASE
    $insertResult = $userCollection->insertOne([
        'email' => $email,
        'fullname' => $fullname,
        'username' => $username,
        'password' => $encryptedPassword,
        'role' => 'user',
        'profilePicture' => new MongoDB\BSON\Binary($profilePicture, MongoDB\BSON\Binary::TYPE_GENERIC),
        'profilePictureType' => $fileType
    ]);

    $userWatchlist->insertOne(['email' => $email, 'role' => 'user']);

    // CHECK IF USER WAS ADDED
    if ($insertResult->getInsertedCount() === 1) {

        $_SESSION['username'] = $username;
        $_SESSION['email'] = $email;
        echo "<script> alert('Registration successful! Welcome, $username.'); 
        window.location.href = 'index.php'; </script>";
        exit();
 
    } else {
        $_SESSION['error'] = 'Failed to register.';
        header("Location: index.php");
        exit();
    }
}

// LOGIN FUNCTION
if (isset($_POST['login'])) {
  $email = $_POST['loginEmail'];
  $password = $_POST['loginPassword'];

  // IS USER ADMIN ?? 
  $admin = $adminCollection->findOne(['email' => $email]);

  if ($admin) {
     // VERIFY ADMIN PASSWORD
      if ($password === $admin['password']) {
          
          $_SESSION['username'] = $admin['username'];
          $_SESSION['email'] = $admin['email'];
          $_SESSION['role'] = 'admin';
          $_SESSION['loggedin'] = true;

          header("Location: index.php#div1");
          exit();
      } else {
          echo "<script>alert('Incorrect password.');
          window.location.href = 'index.php';</script>";
          die(); 
      }
  } else {
      // IS USER USER ??
      $user = $userCollection->findOne(['email' => $email]);
      if ($user) {
        // DECRYPT PASSWORD
        $decryptedPassword = decryptPassword($user['password']); 
        if ($decryptedPassword === $password) { 
            
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['role'] = 'user';
            $_SESSION['loggedin'] = true;
        
            header("Location: index.php#div1");
            exit();

        } else {
            echo "<script>alert('Incorrect password.');
            window.location.href = 'index.php';</script>";
            die(); 
        }
        
      } else {
          echo "<script>alert('User not found.');
          window.location.href = 'index.php';</script>";
          die(); 
      }
  }
}

// LOUGOUT FUNCTION
if (isset($_POST['logout'])) {
    $_SESSION = array();
    session_destroy();
    header("Location: index.php#div1");
    exit();
}

// ADD MOVIE
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['movieImage'])) {
  $movieTitle = $_POST['movieTitle'];
  $movieDescription = $_POST['movieDescription'];
  $section = $_POST['section'];
  $movieTrailer = $_POST['movieTrailer'];
  $movieYear = $_POST['movieYear'];
  $genres = $_POST['genres'];

  if (isset($_FILES['movieImage']) && $_FILES['movieImage']['error'] == 0) {
      $bucket = $databaseConnection->selectDatabase('SignUp')->selectGridFSBucket();

      // Get the image data
      $imageTmpPath = $_FILES['movieImage']['tmp_name'];
      $imageData = file_get_contents($imageTmpPath);

      // Create a stream from the image data
      $stream = fopen('php://memory', 'r+');
      fwrite($stream, $imageData);
      rewind($stream);

      try {
          // Store the image using GridFS
          $fileId = $bucket->uploadFromStream($_FILES['movieImage']['name'], $stream);

          // Save the movie details to the MongoDB collection
          $movieData = [
              'title' => $movieTitle,
              'image_id' => $fileId,
              'description' => $movieDescription,
              'section' => $section,
              'trailer_url' => $movieTrailer,
              'year' => $movieYear, // Add year released
              'genres' => $genres, // Add genres
          ];

          // Insert into the database
          $insertResult = $movieCollection->insertOne($movieData);
          fclose($stream);

      } catch (MongoDB\GridFS\Exception\FileNotFoundException $e) {
          echo"<script>alert('File not found.');
          window.location.href = 'index.php';</script>";
          die();
      }
  } else {
      echo "<script>alert('Failed to upload image.');
      window.location.href = 'index.php';</script>";
      die();
  }
}

// UPDATE MOVIE
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['update_movie'])) {
    $movieId = $_POST['movie_id'];
    $movieTitle = $_POST['movieTitle'];
    $movieDescription = $_POST['movieDescription'];
    $movieTrailer = $_POST['movieTrailer'];

    // Fields to update
    $updateFields = [
        'title' => $movieTitle,
        'description' => $movieDescription,
        'trailer_url' => $movieTrailer,
    ];

    // Update the movie in the database
    try {
        $result = $movieCollection->updateOne(
            ['_id' => new MongoDB\BSON\ObjectId($movieId)],
            ['$set' => $updateFields]
        );

        if ($result->getModifiedCount() > 0) {
            echo "<script>alert('Movie updated successfully!'); window.location.href = 'index.php';</script>";
        } else {
            echo "<script>alert('No changes made or update failed.');</script>";
        }
    } catch (Exception $e) {
        echo "<script>alert('An error occurred: {$e->getMessage()}');</script>";
    }
}

//ADD MOVIE TO WATCHLIST
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['movie_id'])) {
  $email = $_SESSION['email']; 
  $role = $_SESSION['role']; 

  // ADMIN CANNOT ADD TO WATCHLIST
  if ($role === 'admin') {
      echo "<script>alert('Admins cannot add movies to the watchlist.');
      window.location.href = 'index.php';</script>";
      exit();
  }

  $movieId = $_POST['movie_id']; 
  $movieTitle = $_POST['movie_title'];
  $movieDescription = $_POST['movie_description'];
  $imageId = $_POST['image_id'];

  // Create movie data to add
  $movieData = [
      'movie_id' => $movieId,
      'title' => $movieTitle,
      'description' => $movieDescription,
      'image_id' => $imageId,
  ];

  // Fetch the user's watchlist collection
  $userWatchlist = $databaseConnection->selectDatabase('SignUp')->selectCollection('userWatchlist');

  // Check if the user already has a watchlist
  $existingWatchlist = $userWatchlist->findOne(['email' => $email]);

  if ($existingWatchlist) {
      // Check if the movie is already in the watchlist to avoid duplicates
      $isMovieInWatchlist = false;
      foreach ($existingWatchlist['movies'] as $movie) {
          if ($movie['movie_id'] === $movieId) {
              $isMovieInWatchlist = true;
              break;
          }
      }

      if (!$isMovieInWatchlist) {
          // Add the movie to the existing watchlist
          $userWatchlist->updateOne(
              ['email' => $email],
              ['$push' => ['movies' => $movieData]]
          );
          echo "<script>alert('Movie added to the watchlist successfully!');</script>";
      } else {
          echo "<script>alert('This movie is already in your watchlist.');</script>";
      }
  }
  header("Location: index.php#div3");
  exit();
}

// FETCH WATCHLIST FUNCTION
if (isset($_SESSION['email'])) {
  $email = $_SESSION['email'];
  // Fetch the user's watchlist from the database
  $userWatchlist = $databaseConnection->selectDatabase('SignUp')->selectCollection('userWatchlist');
  $watchlistData = $userWatchlist->findOne(['email' => $email]);
  // Get the movies array from the watchlist
  $userMovies = isset($watchlistData['movies']) ? $watchlistData['movies'] : [];
} else {
  $userMovies = [];
}

// REMOVE WATCHLIST FUNCTION
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['remove_movie_id'])) {
  $email = $_SESSION['email'];
  $movieId = $_POST['remove_movie_id'];

  $userWatchlist = $databaseConnection->selectDatabase('SignUp')->selectCollection('userWatchlist');
  
  $userWatchlist->updateOne(
      ['email' => $email], 
      ['$pull' => ['movies' => ['movie_id' => $movieId]]] 
  );

  header("Location: index.php#div3");
  exit();
}

// MOVIE HOMEPAGE DISPLAY FROM DATABASE
$moviesCursor = $movieCollection->find();
$movies = iterator_to_array($moviesCursor);

// IF MOVIE IS CLICKED MOVIE ID WILL GET AND DISPLAY MOVIE DETAILS IN MODAL
$selectedMovie = null;
if (isset($_GET['movie_id'])) {
    $movieId = $_GET['movie_id'];
    try {
        $selectedMovie = $movieCollection->findOne(['_id' => new MongoDB\BSON\ObjectId($movieId)]);
    } catch (Exception $e) {
        echo "Error fetching movie details: " . $e->getMessage();
    }
}

//DISPLAY USERNAME
$username = "";
if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) { 
    $username = $_SESSION['username'];
}

?>

<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="UTF-8" />
  <title>Screen Vault</title>
  <link rel="stylesheet" href="style.css" />
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
  <link href="https://unpkg.com/boxicons@2.0.7/css/boxicons.min.css" rel="stylesheet" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    .hidden {
      display: none;
    }
  </style>
</head>
<body>
  <div class="sidebar">
    <div class="logo-details">
      <i class="bx bxl-vault"></i>
      <div class="logo_name">ScreenVault</div>
      <i class="bx bx-menu" id="btn"></i>
    </div>
    <ul class="nav-list">
      <li>
        <i class="bx bx-search"></i>
        <input type="text" id ="searchInput" placeholder="Search" />
        <span class="tooltip">Search</span>
      </li>
      <li><a href="#div1" id="link1"><i class="bx bx-home"></i><span class="links_name">Home</span></a><span class="tooltip">Home</span></li>

      <!-- ADD MOVIES BUTTON WILL HIDE IF THE USER IS NOT ADMIN -->
      <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
        <?php if ($_SESSION['role'] === 'admin'): ?>
      <li><a href="#div2" id="link2" ><i class="bx bx-film"></i><span class="links_name">Movies</span></a><span class="tooltip">Movies</span></li>
      <?php else: ?>
        <li><a href="#div2" id="link2" style="display:none;" ><i class="bx bx-film"></i><span class="links_name">Movies</span></a><span class="tooltip">Movies</span></li>
        <?php endif; ?>
      <?php endif; ?>


      <li><a href="#div3" id="link3"><i class="bx bx-list-plus"></i><span class="links_name">Watch List</span></a><span class="tooltip">Watch List</span></li>
      <li><a href="#div4" id="link4"><i class="bx bx-group"></i><span class="links_name">About us</span></a><span class="tooltip">About us</span></li>


      <!-- LOGOUT BUTTON WILL SHOW IF THE USER IS LOGGED IN -->
      <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
        <li>
        <form action="" method="POST" style="display: inline;">
        <button type="submit" name="logout" style="background: none; border: none; color: inherit; cursor: pointer;">
          <i class="bx bx-log-out"></i><span class="links_name"></span>
        </button>
        </form>
        <span class="tooltip">Log out</span>
      </li>
      <?php endif; ?>

    </ul>
  </div>

  <div class="SVlogo">
    <img src="./image/SVlogo.png" alt="">
  </div>
  

  <div id="overlay"></div>

  <!-- LOGIN BUTTON WILL SHOW IF NOT LOGGED IN AND IF LOGGED IN IT WILL HIDE -->
  <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
      <button id="form-open" style="display: none;">Login</button>
      <?php else: ?>
      <button id="form-open">Login</button>
      <?php endif; ?>
      
    <!-- PROFILE PICTURE WILL SHOW IF LOGGED IN -->
      <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
    <?php
    // Fetch user data from MongoDB
    $user = $userCollection->findOne(['email' => $_SESSION['email']]);

    // Retrieve profile picture
    if (isset($user['profilePicture'])) {
        // Check if profilePicture is a URL (Google OAuth) or binary data (manual signup)
        if (filter_var($user['profilePicture'], FILTER_VALIDATE_URL)) {
            $profilePicture = $user['profilePicture']; // Use Google profile picture URL
        } else {
            $profilePictureData = base64_encode($user['profilePicture']->getData());
            $profilePictureType = $user['profilePictureType'];
            $profilePicture = "data:{$profilePictureType};base64,{$profilePictureData}"; // Manual signup profile picture
        }
    } else {
        $profilePicture = './image/profile.png'; // Default profile picture
    }
    ?>

  
    <div class="prupayl">
        <div class="uniUser">
            <p><?php echo $_SESSION['username']; ?></p>
        </div>
        <div class="uniProfile">
          
            <img src="<?php echo $profilePicture; ?>" alt="Profile Picture">
        </div>
    </div>
<?php else: ?>
    <div class="prupayl" style="display: none;">
        <div class="uniUser">
            <p><?php echo isset($username) ? $username : ''; ?></p>
        </div>
        <div class="uniProfile">
            <img src="./image/profile.jpg" alt="Default Profile Picture">
        </div>
    </div>
<?php endif; ?>

<?php
// Connect to MongoDB
$databaseConnection = new MongoDB\Client('mongodb://localhost:27017');
$adminNotifCollection = $databaseConnection->SVadmin->adminNotif;

// Fetch the latest notifications, you can customize the query as needed (e.g., limit, sort)
$notifications = $adminNotifCollection->find([], ['sort' => ['timestamp' => -1]]);  // Sorting by timestamp descending
?>

    <!-- NOTIFICATION BTN -->
        <div class="notification-dropdown">
            
            <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
            <?php if ($_SESSION['role'] === 'admin'): ?>
            <img class = "notification-btn"  src="./image/notif.png" onclick="toggleDropdown()">
            <?php endif; ?>
            <?php endif; ?>

            <div id="notificationList" class="notification-list">
                <ul>
                    <?php if ($notifications->isDead()): ?>
                        <li>No new notifications</li>
                    <?php else: ?>
                        <?php foreach ($notifications as $notif): ?>
                            <li>
                                <strong><?php echo htmlspecialchars($notif['notification']); ?></strong><br>
                                <span>Time: <?php echo $notif['timestamp']->toDateTime()->format('Y-m-d H:i:s'); ?></span>
                            </li>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </ul>
            </div>
        </div>

  <!-- FORM FOR LOGIN AND SIGNUP  -->
  <section class="home">
    <div class="form_container">
      <i class="uil uil-times form_close"></i>
      <button class="back_button">Back</button>
      <!-- Login Form -->
      <div class="form login_form">
        <form  id="form1" action="" method="POST">
          <h2>Login</h2>
          <div class="input_box">
            <input type="email" name="loginEmail" id="loginEmail" placeholder="Enter your email" required /> 
            <i class="uil uil-envelope-alt email"></i>
          </div>
          <div class="input_box">
            <input type="password" name="loginPassword" id ="loginPassword" placeholder="Enter your password" required />
            <i class="uil uil-eye-slash pw_hide"></i>
            <i class="uil uil-lock password"></i>
          </div>
          <button class="button" type="submit" name="login">Login Now</button>
          <p><a href="<?= $client->createAuthUrl(); ?>" class="google-login">Login with Google</a></li></p>
          <div class="login_signup">Don't have an account? <a href="#" id="signup">Signup</a></div>
        </form>
      </div>
  
  <!-- Signup Form -->
    <div class="form signup_form">
    <form id="form2" action="" method="POST" enctype="multipart/form-data">
        <h2>Signup</h2>
        <div class="input_box">
        <input type="email" name="signupEmail" id="signupEmail" placeholder="Enter your email" required value="<?= isset($_SESSION['signupData']['signupEmail']) ? htmlspecialchars($_SESSION['signupData']['signupEmail']) : '' ?>" />
        <i class="uil uil-envelope-alt email"></i>
        </div>

        <div class="input_box">
        <input type="text" name="signupFname" id="signupFname" placeholder="Enter your full name" required value="<?= isset($_SESSION['signupData']['signupFname']) ? htmlspecialchars($_SESSION['signupData']['signupFname']) : '' ?>" />
        <i class="uil uil-envelope-alt email"></i>
        </div>

        <div class="input_box">
        <input type="text" name="signupUsername" id="signupUsername" placeholder="Enter a username" required value="<?= isset($_SESSION['signupData']['signupUsername']) ? htmlspecialchars($_SESSION['signupData']['signupUsername']) : '' ?>" />
        <i class="uil uil-envelope-alt email"></i>
        </div>

        <div class="input_box">
        <input type="password" name="signupPassword" id="signupPassword" placeholder="Create password" required value="<?= isset($_SESSION['signupData']['signupPassword']) ? htmlspecialchars($_SESSION['signupData']['signupPassword']) : '' ?>" />
        <i class="uil uil-eye-slash pw_hide"></i>
        <i class="uil uil-lock password"></i>
        </div>

        <div class="input_box">
        <input type="file" class="profileIMG" name="profilePicture" id="profilePicture" accept="image/*" required />
        <i class="uil uil-image"></i>
        </div>

        <div class="input_box">
        <button class="button">Signup Now</button>
        <div class="login_signup">Already have an account? <a href="#" id="login">Login</a></div>
        </div>
        </form>
    </div>

<?php
// After handling form submission and redirect, clear session data
if (isset($_SESSION['signupData'])) {
    unset($_SESSION['signupData']); // Remove the data to avoid retaining on next page load
}
?>

  </section>


<!-- Div 1 - Home -->
<div id="div1" class="DIV1-HOME">
    <!-- Popular Movies Section -->
    <div class="popularMovies">
    <h4>Popular Movies</h4>
    <button class="scroll-button scroll-left" onclick="scrollSectionLeft('popular-movies-cards')">◀</button>
    <button class="scroll-button scroll-right" onclick="scrollSectionRight('popular-movies-cards')">▶</button>
    <div class="popular-movies-cards">
                  <?php foreach ($movies as $movie): ?>
                    <?php if ($movie['section'] === 'popular'): ?>
                  <div class="movie-card">
                      <?php
                      // Fetch image from GridFS and convert to base64
                      $imageId = $movie['image_id'];
                      $bucket = $databaseConnection->selectDatabase('SignUp')->selectGridFSBucket();
                      $stream = $bucket->openDownloadStream($imageId);
                      $imageData = stream_get_contents($stream);
                      $base64Image = base64_encode($imageData);
                      ?>
                      <a href="?movie_id=<?= htmlspecialchars($movie['_id']) ?>"> 
                          <img class="movieImg" src="data:image/jpeg;base64,<?= $base64Image ?>" alt="<?= htmlspecialchars($movie['title']) ?>">
                      </a>
                      <h3 class="<?= strlen($movie['title']) > 30 ? 'long-title' : '' ?>">
                      <?= htmlspecialchars($movie['title']) ?>
                      </h3>

                      <div class="movie-genre" style = "font-size: 0px;" >
                        <p>Genre: <?= htmlspecialchars(implode(', ', (array)$movie['genres'] ?? [])) ?></p>
                      </div>


                                <!-- Add to Watchlist Button -->
                            <form action="" method="POST">
                            <input type="hidden" name="movie_id" value="<?= $movie['_id'] ?>">
                            <input type="hidden" name="movie_title" value="<?= htmlspecialchars($movie['title']) ?>">
                            <input type="hidden" name="image_id" value="<?= $imageId ?>">
                            <button type="submit" class="add-to-watchlist-btn">
                            <i class="fas fa-plus-circle"></i> Add to Watchlist
                            </button>
                            </form>

                            <!-- Edit Button for Admin -->
                            <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                            <form class="updateMovieForm" action="" method="POST">
                                <input type="hidden" name="movie_id" value="<?= $movie['_id'] ?>">
                                <button type="button" class="updateBTN" onclick="openUpdateModal('<?= $movie['_id'] ?>', '<?= htmlspecialchars($movie['title']) ?>', '<?= htmlspecialchars($movie['description']) ?>', '<?= htmlspecialchars($movie['trailer_url']) ?>')">
                                    <i class="fas fa-edit"></i> Edit
                                </button>
                            </form>
                            <?php endif; ?>
                    </div>
         <?php endif; ?>
        <?php endforeach; ?>
    </div>
</div>

    <!-- New Movies Section -->
    <div class="newMovies">
        <h4>New Movies</h4>
        <button class="scroll-button scroll-left" onclick="scrollSectionLeft('new-movies-cards')">◀</button>
        <button class="scroll-button scroll-right" onclick="scrollSectionRight('new-movies-cards')">▶</button>
        <div class="new-movies-cards">
            <?php foreach ($movies as $movie): ?>
                <?php if ($movie['section'] === 'new'): ?>
                  <div class="movie-card">
                        <?php
                        $imageId = $movie['image_id'];
                        $bucket = $databaseConnection->selectDatabase('SignUp')->selectGridFSBucket();
                        $stream = $bucket->openDownloadStream($imageId);
                        $imageData = stream_get_contents($stream);
                        $base64Image = base64_encode($imageData);
                        ?>
                      <a href="?movie_id=<?= htmlspecialchars($movie['_id']) ?>"> 
                          <img class="movieImg" src="data:image/jpeg;base64,<?= $base64Image ?>" alt="<?= htmlspecialchars($movie['title']) ?>">
                      </a>
                        <h3><?= htmlspecialchars($movie['title']) ?></h3>
                        <div class="movie-genre" style = "font-size: 0px;" >
                        <p>Genre: <?= htmlspecialchars(implode(', ', (array)$movie['genres'] ?? [])) ?></p>
                      </div>

                        <!-- Add to Watchlist Button -->
                        <form action="" method="POST">
                            <input type="hidden" name="movie_id" value="<?= $movie['_id'] ?>">
                            <input type="hidden" name="movie_title" value="<?= htmlspecialchars($movie['title']) ?>">
                            <input type="hidden" name="image_id" value="<?= $imageId ?>">
                            <button type="submit" class="add-to-watchlist-btn">
                            <i class="fas fa-plus-circle"></i> Add to Watchlist
                            </button>
                            </form>

                            <!-- Edit Button for Admin -->
                            <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                            <form class="updateMovieForm" action="" method="POST">
                                <input type="hidden" name="movie_id" value="<?= $movie['_id'] ?>">
                                <button type="button" class="updateBTN" onclick="openUpdateModal('<?= $movie['_id'] ?>', '<?= htmlspecialchars($movie['title']) ?>', '<?= htmlspecialchars($movie['description']) ?>', '<?= htmlspecialchars($movie['trailer_url']) ?>')">
                                    <i class="fas fa-edit"></i> Edit
                                </button>
                            </form>
                            <?php endif; ?>

                    </div>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- More Movies Section -->
    <div class="moreMovies">
        <h4>More Movies</h4>
        <div class="more-movies-cards">
            <?php foreach ($movies as $movie): ?>
                <?php if ($movie['section'] === 'more'): ?>
                  <div class="movie-card">
                        <?php
                        $imageId = $movie['image_id'];
                        $bucket = $databaseConnection->selectDatabase('SignUp')->selectGridFSBucket();
                        $stream = $bucket->openDownloadStream($imageId);
                        $imageData = stream_get_contents($stream);
                        $base64Image = base64_encode($imageData);
                        ?>
                      <a href="?movie_id=<?= htmlspecialchars($movie['_id']) ?>"> 
                          <img class="movieImg" src="data:image/jpeg;base64,<?= $base64Image ?>" alt="<?= htmlspecialchars($movie['title']) ?>">
                      </a>
                        <h3><?= htmlspecialchars($movie['title']) ?></h3>
                        <div class="movie-genre" style = "font-size: 0px;" >
                        <p>Genre: <?= htmlspecialchars(implode(', ', (array)$movie['genres'] ?? [])) ?></p>
                      </div>

                        <!-- Add to Watchlist Button -->
                        <form action="" method="POST">
                            <input type="hidden" name="movie_id" value="<?= $movie['_id'] ?>">
                            <input type="hidden" name="movie_title" value="<?= htmlspecialchars($movie['title']) ?>">
                            <input type="hidden" name="image_id" value="<?= $imageId ?>">
                            <button type="submit" class="add-to-watchlist-btn">
                            <i class="fas fa-plus-circle"></i> Add to Watchlist
                            </button>
                            </form>

                            <!-- Edit Button for Admin -->
                            <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                            <form class="updateMovieForm" action="" method="POST">
                                <input type="hidden" name="movie_id" value="<?= $movie['_id'] ?>">
                                <button type="button" class="updateBTN" onclick="openUpdateModal('<?= $movie['_id'] ?>', '<?= htmlspecialchars($movie['title']) ?>', '<?= htmlspecialchars($movie['description']) ?>', '<?= htmlspecialchars($movie['trailer_url']) ?>')">
                                    <i class="fas fa-edit"></i> Edit
                                </button>
                            </form>
                            <?php endif; ?>

                    </div>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    </div>
</div>

  <!-- Div 2 - Movies -->
<div id="div2" class="admin hidden">
      <div  class="movie-container">
        <h2>Welcome Admin</h2>
        <p>Use the form below to add new movies</p>
  
        <div class="movie-cards">
        </div>

        <!-- FORM NG MOVIES -->
        <div class="movie-form">
          <h3>Add a New Movie</h3>

          <form action="" method="POST" enctype="multipart/form-data">
          
            <label for="movie-title">Movie Title:</label>
            <input id="movieTitleInput" name="movieTitle" type="text" placeholder="Enter movie title" required>

            <label for="movie-image">Movie Image:</label>
            <input id="movieImageInput" name="movieImage" type="file" accept="image/*" required>
          
            <label for="movie-description">Movie Description:</label>
            <textarea id="movieDescriptionInput" name="movieDescription" placeholder="Enter movie description" required></textarea>

            <label for="movie-trailer">Movie Trailer URL:</label>
            <input id="movieTrailerInput" name="movieTrailer" type="text" placeholder="Enter trailer URL" required>
          
            <label for="Sections">Choose a Section:</label>
            <select id="sectionInput" name="section">
                <option value="popular">Popular</option>
                <option value="new">New</option>
                <option value="more">More</option>
            </select>

            <label for="genres">Choose Genres:</label>
            <select id="genresInput" name="genres[]" multiple>
              <option value="action">Action</option>
              <option value="adventure">Adventure</option>
              <option value="comedy">Comedy</option>
              <option value="drama">Drama</option>
              <option value="horror">Horror</option>
              <option value="romance">Romance</option>
              <option value="sci-fi">Sci-Fi</option>
              <option value="thriller">Thriller</option>
              <option value="animation">Animation</option>
              <option value="sport">Sport</option>
            </select>

            <label for="movie-year">Year Released:</label>
            <input id="movieYearInput" name="movieYear" type="text" placeholder="Enter movie year" required>

            <div class="form-buttons">
              <button type="submit" id="add-movie-btn">Add Movie</button>
            </div>
          </form>
  </div>
  </div>
  </div>

<!-- Div 3 - Watchlist -->
<div id="div3" class="watchlist-body hidden">
        <h4>My Watchlist</h4>
          <div class="watchlist-movies-cards">
              <?php if (!empty($userMovies)): ?>
              <?php foreach ($userMovies as $movie): ?>
                  <div class="movie-card">
              <?php
              // GET MOVIE IMAGE FROM DATABASE
              $imageId = $movie['image_id'];
              $bucket = $databaseConnection->selectDatabase('SignUp')->selectGridFSBucket();
              $stream = $bucket->openDownloadStream(new MongoDB\BSON\ObjectId($imageId));
              $imageData = stream_get_contents($stream);
              $base64Image = base64_encode($imageData);
              ?>
              <!-- DISPLAY MOVIE IMAGE TO WATCHLIST -->
              <img class="movieImg" src="data:image/jpeg;base64,<?= $base64Image ?>" alt="<?= htmlspecialchars($movie['title']) ?>">
              <h3><?= htmlspecialchars($movie['title']) ?></h3>
              <!-- REMOVE MOVIE FROM WATCHLIST -->
              <form class="removeform" method="POST" action="">
                <input type="hidden" name="remove_movie_id" value="<?= htmlspecialchars($movie['movie_id']) ?>">
                <button type="submit" class="remove-from-watchlist"><i class="fa-solid fa-trash"></i>Remove</button>
              </form>
              </div>
              <?php endforeach; ?>
              <?php else: ?>
                  <p>Your watchlist is empty.</p>
              <?php endif; ?>
          </div>
</div>

<!-- End of Div 3  -->

<div id="div4" class="hidden"> 
<header class="hidir">
    <h1>
      <span class="Screen">Screen</span>
      <span class="Vault">Vault</span>
    </h1>
    <h2>
      The web app simplifies choosing movies by offering a curated watchlist with ratings and reviews, helping users quickly find what to watch and enhancing their viewing experience.
      Develop a user-friendly single-page application (SPA) for managing watchlists, allowing users to discover, add, and categorize movies. The app provides smooth navigation, efficient access to movie details, a search feature to find films by title, genre, or actor, and options for rating and reviewing to foster community engagement.
    </h2>
  </header>
  <h2 class="team"><i class="fa-solid fa-user">   Meet Our Team!</i></h2>
  <div class="grid-container">
    <div class="team-member">
      <img src="https://scontent.fmnl25-6.fna.fbcdn.net/v/t39.30808-1/456954308_1859632294525810_3782408096132360801_n.jpg?stp=dst-jpg_s200x200_tt6&_nc_cat=102&ccb=1-7&_nc_sid=0ecb9b&_nc_eui2=AeFaondcEWX7JCpySL-MAPBYQxexsUCV6XVDF7GxQJXpdRE0Nqh-VvdzJeexQlBECtirSXzv6SpeElYuh2fff4mt&_nc_ohc=dUl0iCoiALAQ7kNvgHw-Dk-&_nc_zt=24&_nc_ht=scontent.fmnl25-6.fna&_nc_gid=AwO_OcwYSbxpx4vbZpgmXWD&oh=00_AYCFfVKnJjHZvXUs6aLuHZ-Cm6Dp7JTbjJUFrgRTKmGBAA&oe=675DBFED
        " alt="salva">
      <h3 class="team-name">JOHN CARLO E. SALVA</h3>
      <p1>LEADER</p1>
      <p>Backend Developer</p>
    </div>

    <div class="team-member">
        <img class="pogi"src="image\MIKE.png"
         alt="mike">
        <h3 class="team-name">CHRISTIAN MIKE B. PAGASIAN</h3>
        <p1>ASSISTANT LEADER</p1>
        <p>Backend Developer</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl40-2.fna.fbcdn.net/v/t39.30808-6/423237478_24955395580772871_990491708606960746_n.jpg?stp=dst-jpg_s206x206_tt6&_nc_cat=108&ccb=1-7&_nc_sid=fe5ecc&_nc_eui2=AeFt_C8eGau3jLes--QlPcWUZau5vV8gxdBlq7m9XyDF0A4-tosC-GEUPuUgwYL86XtW9ThAHDu94EV_XMtS0jYL&_nc_ohc=Hd9Qm0zB1y4Q7kNvgGKL7tF&_nc_zt=23&_nc_ht=scontent.fmnl40-2.fna&_nc_gid=AlVx8cd1PxYPXUmtcYDn_cw&oh=00_AYBiWxnYGPYggBENb0fjRavPxtDLTEt9r0QzncXd86l0eA&oe=675B194F"alt="payapag">
        <h3 class="team-name">AVRIL JUSTIN F. PAYAPAG</h3>
        <p1>MEMBER</p1>
        <p>Frontend Developer</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl40-1.fna.fbcdn.net/v/t39.30808-1/454780457_1161609165061549_1142051407801420758_n.jpg?stp=dst-jpg_s200x200_tt6&_nc_cat=102&ccb=1-7&_nc_sid=0ecb9b&_nc_eui2=AeHgdwkZjRIzN0s07FG5OkRwS8snzIsl1GZLyyfMiyXUZtuHYHtpSBjpXaNlXiijPnkUrvtlohXdPvGz94aJvuzd&_nc_ohc=8tzSS7oKm2sQ7kNvgFo5Gqp&_nc_zt=24&_nc_ht=scontent.fmnl40-1.fna&_nc_gid=A1fUWse2xFP2-G9EK_Aha1W&oh=00_AYAXBFIoLBgzeFb9NJabo0xHZVf8bj8AgE2R1jnHdHvpfQ&oe=675AE756" alt="mimi">
        <h3 class="team-name">IMEE E. GALLARDO</h3>
        <p1>MEMBER</p1>
        <p>Frontend Developer</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl40-1.fna.fbcdn.net/v/t39.30808-1/290068302_1182180619018636_4423675895280363672_n.jpg?stp=dst-jpg_s200x200_tt6&_nc_cat=103&ccb=1-7&_nc_sid=0ecb9b&_nc_eui2=AeGKlRSHuiqGfvaFUmWXgvc0aTNGz4cabjtpM0bPhxpuO_A9IokxruP_JwfhVamuA3Tb2_5DBIf3OSUMHmTNY5Yq&_nc_ohc=D43Pybb0cVMQ7kNvgGQ31k6&_nc_zt=24&_nc_ht=scontent.fmnl40-1.fna&_nc_gid=AojTLihnxrgFItuv1seBosP&oh=00_AYDj3jYiB7VRAqw3YeSwABB8wIOGzfB9ela-nBU7-pwvHA&oe=675AFD58" alt="hintapan">
        <h3 class="team-name">REYMARK A. HINTAPAN</h3>
        <p1>MEMBER</p1>
        <p>Documentation & UI/UX Designer</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl40-2.fna.fbcdn.net/v/t39.30808-6/294791364_1096040361006906_4754695849066321364_n.jpg?stp=dst-jpg_s206x206_tt6&_nc_cat=100&ccb=1-7&_nc_sid=fe5ecc&_nc_eui2=AeE9kyvWuCeQt3OU7oq9yBVopRQDEY3lawqlFAMRjeVrCgnSHwE0czm6xtSTpEAzkrnUH2-CgNPCSxK0YNDm2v48&_nc_ohc=71Fumtl6XFQQ7kNvgHFuewg&_nc_zt=23&_nc_ht=scontent.fmnl40-2.fna&_nc_gid=Ao9IbI-6rQfGJLq8NxvUtLF&oh=00_AYDfXWZ1g3EIXoHKnmln7WoSuiUUtIhuTQascDPvVz2WBw&oe=675AF6E0" alt="alag">
        <h3 class="team-name">JOHN CHRISTIAN S. ALAG</h3>
        <p1>MEMBER</p1>
        <p>Documentation</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl40-2.fna.fbcdn.net/v/t39.30808-6/412868586_925215689195018_4064970403589301030_n.jpg?_nc_cat=110&ccb=1-7&_nc_sid=6ee11a&_nc_eui2=AeEjKltfdNe0QInDDORb4fwB_fyL8YjKm1L9_IvxiMqbUhhLZwS8EnXlScvFMk-i1RRpffg7LDJZUWsBX1u32KSC&_nc_ohc=7LT4cncccC0Q7kNvgFlI07E&_nc_zt=23&_nc_ht=scontent.fmnl40-2.fna&_nc_gid=Ah0XQh3as9WRKXSPURqAeeK&oh=00_AYAYrs9at86HdZE5aSffipfsNk-y6RjqUOONcms1P7_qqQ&oe=675AEE26" alt="quindoza">
        <h3 class="team-name">EFRILYN R. QUINDOZA</h3>
        <p1>MEMBER</p1>
        <p>Documentation</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl40-1.fna.fbcdn.net/v/t39.30808-1/449350803_3601569863492531_6277675201060595987_n.jpg?stp=dst-jpg_s200x200_tt6&_nc_cat=101&ccb=1-7&_nc_sid=0ecb9b&_nc_eui2=AeFsJcwk5873cUjHYFUk2hT26Zm3QJcNSjPpmbdAlw1KM2VieUOeun3Rpz4riTRA-of-_HQ3WBSVk2TPVYli871u&_nc_ohc=IWmPPd8Go2UQ7kNvgEvCmX_&_nc_zt=24&_nc_ht=scontent.fmnl40-1.fna&_nc_gid=A2T8tv1fnfFc6ZQroqYjf5w&oh=00_AYAu2T1vOlVSr_r_6OyDgN5ZKjox8fdzjG4ZHgkfk2BL8A&oe=675B13A5" alt="secuya">
        <h3 class="team-name">LHORIVEL A. SECUYA</h3>
        <p1>MEMBER</p1>
        <p>Documentation</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl30-2.fna.fbcdn.net/v/t1.6435-9/131552632_2726277254369759_989197355589379403_n.jpg?_nc_cat=111&ccb=1-7&_nc_sid=a5f93a&_nc_eui2=AeGNc29p7dBkyYxp_Mr6cmHyluE83utNw6GW4Tze603DofHwbdTbokCtFfcSp3NwoY_cm0qidBCkK92gry9MquBx&_nc_ohc=7xP8alxin50Q7kNvgH0SPRg&_nc_zt=23&_nc_ht=scontent.fmnl30-2.fna&_nc_gid=A5_R58njMQsPBCeDtSroU87&oh=00_AYBgpVya9JHKOLwQzTUeZa8lOOEVLzwwhYljPtHqe3Ed4Q&oe=67697E86" alt="santiago">
        <h3 class="team-name">PEABO BRYSON M. SANTIAGO</h3>
        <p1>MEMBER</p1>
        <p>Documentation</p>
    </div>

    <div class="team-member">
        <img src="https://scontent.fmnl30-3.fna.fbcdn.net/v/t1.6435-9/80978686_2496349770642142_838943606969466880_n.jpg?stp=c0.66.600.600a_dst-jpg_s206x206_tt6&_nc_cat=101&ccb=1-7&_nc_sid=50ad20&_nc_eui2=AeGV2ye_u9oNGndoRF3drY8dxmzxH6Bj-V_GbPEfoGP5Xz5mbb7__MsO8ZJE5HHyIVOiFNVOGV1EbasvXNUrnPkY&_nc_ohc=ZF8drRfEeRAQ7kNvgFL0_ZQ&_nc_zt=23&_nc_ht=scontent.fmnl30-3.fna&_nc_gid=AJ0YFacCkgg1BQX03G541df&oh=00_AYDGFgJhQT7R-CO0HSNEw4-wbvZFD0UG2TUIZZCYocbZhA&oe=676984FE" alt="yugto">
        <h3 class="team-name">JULLIUS ASYLL T. YUGTO</h3>
        <p1>MEMBER</p1>
        <p>Documentation</p>
    </div>
    
    <div class="team-member">
        <img src="image\corde.png " alt="corde">
        <h3 class="team-name">MA. KAREN N. CORDE</h3>
        <p1>MEMBER</p1>
        <p>Documentation</p>  
    </div>

    <footer>
    <div class="footer-content">
        <p>&copy; 2024 ScreenVault. All Rights Reserved.</p>
        <ul>
        <li><a href="#">Privacy Policy</a></li>
        <li><a href="#">Terms of Service</a></li>
        <li><a href="#">Contact Us</a></li>
        </ul>
    </div>
    </footer>
  </div>
</div>



<!-- MOVIE MODAL  -->
<div id="div5" class="movieForm <?= $selectedMovie ? '' : 'hidden' ?>">  
    <a href="index.php"><button class="backBtn">Back</button></a>
    <!-- GET THE INFORMATION OF SELECTED MOVIE FROM DATABASE -->
    <?php if ($selectedMovie): ?>
        <div class="movieInfo">
            <iframe width="730" height="415"
            src="https://www.youtube.com/embed/<?= urlencode($selectedMovie['trailer_url']); ?>?autoplay=1&controls=0&showinfo=0&loop=1&playlist=<?= urlencode($selectedMovie['trailer_url']);?>&modestbranding=1&rel=0&iv_load_policy=3&cc_load_policy=0"
             allowfullscreen>
            </iframe>

            <div class="movieDtails">
            <div id="movieTitle" class="<?= strlen($selectedMovie['title']) > 30 ? 'long-title' : '' ?>">
                <p><?= htmlspecialchars($selectedMovie['title']) ?></p>
            </div>

            <div id="movieGenre">
                <p>Genre: <?= htmlspecialchars(implode(', ', (array)$selectedMovie['genres'] ?? [])) ?></p>
            </div>

            <div id="movieYear">
                <p>Year: <?= htmlspecialchars($selectedMovie['year']) ?></p>
            </div>

            <div id="movieDescription">
                <p><?= htmlspecialchars($selectedMovie['description']) ?></p>  
            </div>
            </div>

            <div id="movieRatingContainer">
                <p id="movieRatingTitle">User Comments</p>
                <div id="movieRating">



          <!--PROFILE PICTURE -->
          <div class="profile-picture">
          <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
          <?php

          $user = $userCollection->findOne(['email' => $_SESSION['email']]);

          //GET PROFILE PICTURE
          if (isset($user['profilePicture'])) {
          // GOOGLE PROFILE PICTURE
          if (filter_var($user['profilePicture'], FILTER_VALIDATE_URL)) {
            $profilePicture = $user['profilePicture'];
          } else {
            $profilePictureData = base64_encode($user['profilePicture']->getData());
            $profilePictureType = $user['profilePictureType'];
            $profilePicture = "data:{$profilePictureType};base64,{$profilePictureData}"; 
          }
          } else {
          $profilePicture = './image/profile.png'; 
          }
        ?>
        <img src="<?php echo $profilePicture; ?>" alt="Profile Picture">
        <?php else: ?>
        <img src="./image/profile.png" alt="Default Profile Picture">
        <?php endif; ?>
        </div>

        <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // First, check if the delete comment request was made
    if (isset($_POST['deleteComment'])) {
        // Delete comment logic
        $commentId = $_POST['deleteCommentId'];
        $movieId = $_POST['movieId'];

        // MongoDB delete operation: remove the comment
        $databaseConnection = new MongoDB\Client('mongodb://localhost:27017');
        $movieCollection = $databaseConnection->MovieCollection->movies;
        
        $movieCollection->updateOne(
            ["_id" => new MongoDB\BSON\ObjectId($movieId)],
            ['$pull' => ['comments' => ['comment' => $commentId]]]
        );

        echo "<script>
            alert('Comment deleted successfully.');
            window.location.href = 'index.php';
        </script>";
        exit;
    }

    // Check if the user is logged in before posting a comment or rating
    if (!isset($_SESSION['loggedin']) || !$_SESSION['loggedin']) {
        echo "<script>
            alert('Please log in to post a comment or rating');
            window.location.href = 'index.php';
        </script>";
        exit;
    }

    // Posting comment and rating logic
    $movieId = $_POST['movieId'];
    $comment = trim($_POST['comment']);
    $rating = intval($_POST['rating'] ?? 0);
    $username = $_SESSION['username'];

    if (empty($comment) && $rating <= 0) {
        echo "<script>
            alert('Please provide a comment or rating');
            window.location.href = 'index.php';
        </script>";
        exit;
    }

    // FETCH MOVIE FROM DATABASE
    $databaseConnection = new MongoDB\Client('mongodb://localhost:27017');
    $movieCollection = $databaseConnection->MovieCollection->movies;
    $selectedMovie = $movieCollection->findOne(["_id" => new MongoDB\BSON\ObjectId($movieId)]);

    // Get the movie title
    $movieTitle = $selectedMovie['title'] ?? 'Unknown Movie';  // Default to 'Unknown Movie' if not found

    // RATING CONDITION // CHECK IF USER ALREADY RATED
    $comments = $selectedMovie['comments'] ?? [];
    $alreadyRated = false;
    foreach ($comments as $commentData) {
        if ($commentData['username'] === $username && !empty($commentData['rating'])) {
            $alreadyRated = true;
            break;
        }
    }

    if ($alreadyRated && $rating > 0) {
        echo "<script>
            alert('You have already rated this movie.');
            window.location.href = 'index.php';
        </script>";
        exit;
    }

    // USER PROFILE PICTURE
    $user = $userCollection->findOne(['email' => $_SESSION['email']]);
    if (isset($user['profilePicture'])) {
        // GOOGLE PROFILE PICTURE
        if (filter_var($user['profilePicture'], FILTER_VALIDATE_URL)) {
            $userProfile = $user['profilePicture']; 
        } else { 
            // USER PROFILE PICTURE FROM DATABASE
            $profilePictureData = base64_encode($user['profilePicture']->getData());
            $profilePictureType = $user['profilePictureType'];
            $userProfile = "data:{$profilePictureType};base64,{$profilePictureData}";
        }
    } else {
        // PROFILE PICTURE IF NOT LOGGED IN
        $userProfile = './image/profile.png';
    }

    // ADD COMMENT AND RATING TO DATABASE
    $newComment = [
        "username" => $username,
        "profile" => $userProfile,
        "comment" => $comment,
        "rating" => $rating
    ];

    $movieCollection->updateOne(
        ["_id" => new MongoDB\BSON\ObjectId($movieId)],
        ['$push' => ["comments" => $newComment]]
    );

    // FUNCTION TO ADD NOTIFICATION TO ADMINNOTIF COLLECTION
    function notifyAdmin($movieId, $movieTitle, $comment, $rating, $username) {
        $adminNotifCollection = $GLOBALS['databaseConnection']->SVadmin->adminNotif;
        $adminNotifCollection->insertOne([
            'movieId' => $movieId,
            'username' => $username,
            'notification' => "{$username} added a comment to '{$movieTitle}' with a rating of {$rating}",
            'comment' => $comment,
            'rating' => $rating,
            'timestamp' => new MongoDB\BSON\UTCDateTime()
        ]);
    }

    // CALL NOTIFICATION FUNCTION WITH MOVIE TITLE AND RATING
    notifyAdmin($movieId, $movieTitle, $comment, $rating, $username);

    // AFTER POSTING COMMENT AND RATING IT WILL LOAD 
    echo "<script>
        window.location.href = 'index.php#div5';
    </script>";
    exit;
}
?>


    <!-- Display Comments -->
    <?php
    $comments = $selectedMovie['comments'] ?? [];
    foreach ($comments as $comment): ?>

        <div id="greatestComment">
                <!-- Profile Picture -->
                <div class="profile-picture">
                    <img src="<?= htmlspecialchars($comment['profile'] ?? './image/profile.png'); ?>" alt="User Profile Picture">
                </div>

                <!-- Username -->
                <div id="UserRating"><?= htmlspecialchars($comment['username']); ?></div>

                <!-- User Rating -->
                <?php if (!empty($comment['rating']) && $comment['rating'] > 0): ?>
                    <div class="user-rating">
                        <?php
                        $rating = $comment['rating'];
                        for ($i = 1; $i <= 5; $i++): ?>
                            <span class="<?= $i <= $rating ? 'selected' : ''; ?>">★</span>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>

                <!-- Comment -->
                <div id="movieRatingComment">
                    <input
                    type="text"
                    id="movieRatingComment_<?= htmlspecialchars($comment['comment']); ?>"
                    class="movieRatingComment"
                    value="<?= htmlspecialchars($comment['comment']); ?>"
                    readonly
                ></div>

                <!-- DELETE AND UPDATE COMMENT -->        
                <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
                <?php if ($_SESSION['role'] === 'admin'): ?>
                    <!-- Admin: Display Delete Button -->
                    <form action="" method="POST" style="display: inline;">
                        <input type="hidden" name="deleteCommentId" value="<?= htmlspecialchars($comment['comment']); ?>">
                        <input type="hidden" name="movieId" value="<?= htmlspecialchars($movieId); ?>">
                        <button class="deleteComment" type="submit" name="deleteComment">Delete</button>
                    </form>
                <?php endif; ?>
                <?php endif; ?>
                </div>
    <?php endforeach; ?>


              <!-- USERNAME AND COMMENTS // POST -->
              <form id="movieRatingComment" action="" method="POST">
                  <?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
                      <p id="UserRating"><?= htmlspecialchars($_SESSION['username']); ?></p>
                  <?php endif; ?>

                  <input type="hidden" name="movieId" value="<?= htmlspecialchars($movieId); ?>">
                  <!-- STAR RATING -->
                  <div class="star-rating-input">
                      <span data-value="1">★</span>
                      <span data-value="2">★</span>
                      <span data-value="3">★</span>
                      <span data-value="4">★</span>
                      <span data-value="5">★</span>
                      <input type="hidden" name="rating" id="rating-value" value="0" require>
                  </div>

                  <input id="movieRatingInput" name="comment" type="text" placeholder="Write a comment..." require>
                  <button id="movieRatingSubmit">Post</button>
              </form>
            </div>
            </div>
            </div>
        <?php else: ?>
            <p>Select a movie to see its details.</p>
        <?php endif; ?>

    </div>

    <div id="updateModal" style="display: none;">
    <div style="background: white; padding: 20px; border-radius: 8px; width: 400px; margin: auto; text-align: center;">
        <h2>Edit Movie</h2>
        <form method="POST" action="">
            <input type="hidden" name="movie_id" id="updateMovieId">
            <label for="movieTitle">Title:</label>
            <input type="text" id="updateMovieTitle" name="movieTitle" required><br><br>
            <label for="movieDescription">Description:</label>
            <textarea id="updateMovieDescription" name="movieDescription" required></textarea><br><br>
            <label for="movieTrailer">YouTube URL:</label>
            <input type="text" id="updateMovieTrailer" name="movieTrailer" required><br><br>
            <button type="submit" name="update_movie">Save Changes</button>
            <button type="button" onclick="closeUpdateModal()">Cancel</button>
        </form>
    </div>
</div>

  <script src="index.js"></script>
  <script src="showDiv.js"></script>
  <script src="login.js"></script>
  <script src="starRating.js"></script>
  <script src="search.js"></script>
 <script src="SnupInput.js"></script>
 <script src="updateMovie.js"></script>
  <script src="/TOTOONATO/notif.js"></script>

</body>
</html>


<!-- TO DO
    SEARCH FILTERING NG MOVIES 80% // ONTING LINIS PA - 
    REVIEW NG MOVIES -
    ADMIN EDIT AND MODIFICATION OF USER COMMENTS
    -->
