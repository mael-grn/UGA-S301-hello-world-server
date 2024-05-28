const path = require('path');

const express = require('express');
const app = express();
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const jwt = require('jsonwebtoken');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const dbPath = path.join(process.cwd(), 'data.db');
const saltRounds = 10;


const db = new sqlite3.Database(dbPath);

// Middleware pour autoriser toutes les origines (attention en production)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200); // Répondre favorablement aux requêtes OPTIONS
  }
  next();
});

// Création des tables
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS professeur (login TEXT PRIMARY KEY, prenom TEXT, nom TEXT, dateNaiss DATE, password TEXT, lastConnexion DATE)");
  db.run("CREATE TABLE IF NOT EXISTS groupe (id TEXT PRIMARY KEY, niveau TEXT, dateCreation DATE, professeur TEXT,difficulte TEXT, FOREIGN KEY (professeur) REFERENCES professeur(login))");
  db.run("CREATE TABLE IF NOT EXISTS eleve (login TEXT PRIMARY KEY, prenom TEXT, nom TEXT, dateNaiss DATE, password TEXT, consentement TEXT, groupeId TEXT,qcm TEXT,tuto TEXT,lastConnexion DATE, FOREIGN KEY (groupeId) REFERENCES groupe(id))"); 
  db.run("CREATE TABLE IF NOT EXISTS informatico (login TEXT PRIMARY KEY, sentences TEXT, FOREIGN KEY (login) REFERENCES eleve(login))");
  db.run("CREATE TABLE IF NOT EXISTS squisine (login TEXT PRIMARY KEY, etat TEXT, tour TEXT, groupeId TEXT, coequipier TEXT, FOREIGN KEY (groupeId) REFERENCES groupe(id))");
});



// Utilisation du middleware dans une route protégée
app.get('/checkToken', (req, res) => {
  const { token } = req.query;

  console.log('token : '+ token);

  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token invalide' });
    }
  });
  
});

// Endpoint pour l'inscription d'un utilisateur ------------------------------------------------------------------------
app.post('/register', (req, res) => {
  
  const { prenom, nom, dateNaiss, password, teacher = false, accordParent } = req.body;
  console.log(`Demande d'inscription reçue : ${prenom}, ${nom}, date de naissance : ${dateNaiss}, professeur : ${teacher}, accord parental : ${accordParent}`);
  //calculer l'age de l'utilisateur
  const userDOB = new Date(dateNaiss);
  const currentDate = new Date();
  const fifteenYearsAgo = new Date(currentDate.getFullYear() - 15, currentDate.getMonth(), currentDate.getDate());

  // si l'utilisateur à moins de 15 ans, et qu'on a pas l'accord parental, alors erreur
  /*if (userDOB >= fifteenYearsAgo && !accordParent) {
    return res.status(400).json({ error: 'Vous devez avoir au moins 15 ans pour vous inscrire.' });//envoyer mail aux parents à la place.
  }*/


  // Créer un login basé sur les règles spécifiées
  const loginAttempt = `${nom.slice(0, 3)}${prenom.charAt(0)}`.toLowerCase();


  
  // Fonction pour generer un nouveau login, n'existant pas dans la base de données, et ajouter l'utilisateur à la base.
  // Note : mettre l'ajout de l'utilisateur et la generation du login est preferable, due à l'asynchronisme des requete SQL
  const registerUserWithLogin = (login, attemptNumber = 0) => {

    //generation d'un login, avec un nombre selon ce que contient attemptNumber
    const proposedLogin = attemptNumber === 0 ? login : `${login}${attemptNumber}`;

    //on recupere les données de la base pour les professeur et eleve de login proposedLogin
    db.get('SELECT login FROM professeur WHERE login = ? UNION SELECT login FROM eleve WHERE login = ?', [proposedLogin, proposedLogin], (err, row) => {

      //Affichage et retours d'une erreur si celle si se produit
      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message});
      }

      //s'il y a des row de retourné, alors le login existe, et on recommence avec une nouvelle variation
      if (row) {
        console.log(`\t-> l'utilisateur ${proposedLogin} existe déjà, generation d'un nouveau login`);
        registerUserWithLogin(login, attemptNumber + 1);
      } 
      //si le login n'existe pas, alors on insert les données
      //
      else {
        const salt = bcrypt.genSaltSync(saltRounds);
        const hash = bcrypt.hashSync(password,salt);
        //traitement du cas on il s'agit d'un professeur
        if (!teacher) {
          db.run(`INSERT INTO eleve (login, prenom, nom, dateNaiss, password, consentement,qcm,tuto,lastConnexion) VALUES (?, ?, ?, ?, ?, ?,'false,false,false,false','false,false,false,',CURRENT_DATE)`,
            [proposedLogin, prenom, nom, dateNaiss, hash, accordParent],
            function (err) {
              if (err) {
                console.error(err);
                return res.status(500).json({ error: err.message });
              }
              const token = jwt.sign({ userId: proposedLogin }, 'secret', { expiresIn: '1h' });
              res.status(200).json({ message: 'success', login: proposedLogin, token:token});
              console.log(`\t-> Inscription de ${proposedLogin} (${nom}, ${prenom}, ${dateNaiss}, Eleve)`);
          }); 
        } 
        //traitement du cas ou il s'agit d'un eleve
        else {
          db.run(`INSERT INTO professeur (login, prenom, nom, dateNaiss, password, lastConnexion) VALUES (?, ?, ?, ?, ?,CURRENT_DATE)`,
            [proposedLogin, prenom, nom, dateNaiss, hash],
            function (err) {
              if (err) {
                console.error(err);
                return res.status(500).json({ error: err.message });
              }
              const token = jwt.sign({ userId: proposedLogin }, 'secret', { expiresIn: '1h' });
              res.status(200).json({ message: 'success', login: proposedLogin, token:token });
              console.log(`\t-> Inscription de ${proposedLogin} (${nom}, ${prenom}, ${dateNaiss}, Professeur)`);
            });
        }
      }
    });
  };

  //inscrire l'utilisateur
  registerUserWithLogin(loginAttempt, 0);
});

// Endpoint pour l'ajout d'un groupe pour un utilisateur ------------------------------------------------------------------------
// Permet d'ajouter un etudiant à un groupe donné
app.post('/addStudentGroup', (req, res) => {
  const { login, groupe } = req.body; // Récupérer les données depuis le corps de la requête
  console.log(`Demande de mise a jour de groupe reçue : groupe ${groupe} pour ${login}`);
  db.run(`UPDATE eleve SET groupeId = ? WHERE login = ?`, [groupe, login], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    } else {

      db.get('SELECT * FROM eleve WHERE login = ?', [login], (err, row) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: err.message });
        }
        if (!row) {
          console.log('\t-> L\'eleve n\'a pas été ajouté');
          return res.status(401).json({ error: `Unauthorized` });
        }
        console.log('\t-> Row après mise à jour : ', row);
        return res.status(200).json({ message: 'success' });

      });
    }
  });
});

// Endpoint pour l'ajout d'un groupe ------------------------------------------------------------------------
// Permet d'ajouter un groupe à un professeur donné
app.post('/addGroup', (req, res) => {
  const { id, niveau, professeur } = req.body;
  console.log(`Nom du groupe et le prof référent ${id}  ${professeur}`);

  db.run(`INSERT INTO groupe (id, niveau, dateCreation, professeur,difficulte) VALUES (?, null, CURRENT_TIMESTAMP, ?,'2,2,2,2')`,
    [id, professeur],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
      } else {
        res.status(200).json({ message: 'success' });
      }
    });
});


// Endpoint pour la verification d'un utilisateur ------------------------------------------------------------------------
app.get('/user', (req, res) => {
  const { login, password, teacher = false } = req.query;
  console.log(`demande de connexion reçue de la part de ${login}`);  
  
  // Recherche dans la base de données SQLite pour trouver une correspondance dans le cas de l'eleve
  db.get('SELECT login, password, prenom, nom, groupeId, false AS teacher FROM eleve WHERE login = ? UNION SELECT login, password, prenom, nom, NULL AS groupeId, true AS teacher FROM professeur WHERE login = ?', [login, login], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({error: err.message});
    }
    if (row) {
      // Si l'utilisateur correspondant est trouvé, comparer les mots de passe
      bcrypt.compare(password, row.password, (compareErr, isMatch) => {
        if (compareErr) {
          console.error(compareErr);
          return res.status(500).json({ error: compareErr.message });
        }

        if (isMatch) {
          // Mise à jour de lastConnexion avec la date courante
          const currentDate = new Date().toISOString();
          const table = teacher ? 'professeur' : 'eleve';
          db.run(`UPDATE ${table} SET lastConnexion = ? WHERE login = ?`, [currentDate, login], (updateErr) => {
            if (updateErr) {
              console.error(updateErr);
              return res.status(500).json({ error: updateErr.message });
            }

            console.log(`\t-> Utilisateur trouvé : ${row.nom} ${row.prenom}, Mot de passe correct, autorisation de connexion`);
            const token = jwt.sign({ userId: row.login }, 'secret', { expiresIn: '1h' });
            return res.status(200).json({
              message: 'success',
              login: row.login,
              nom: row.nom,
              prenom: row.prenom,
              group: row.groupeId,
              teacher: row.teacher,
              group: row.groupeId,
              token: token,
            });
          });
        } else {
          console.log(`\t-> Utilisateur trouvé : ${row.nom} ${row.prenom}, Mot de passe incorrect, refus de la connexion`);
          // Si le mot de passe ne correspond pas, renvoyer une erreur d'authentification
          return res.status(401).json({ error: 'Unauthorized' });
        }
      });
    } else {
      // Aucun utilisateur trouvé
      console.log(`\t-> Aucun utilisateur trouvé pour : ${login}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }
  });
});

// Endpoint pour récupérer les groupes d'un professeur spécifique------------------------------------------------------------------------
app.get('/getGroupesDuProf', (req, res) => {
  const { prof } = req.query;
  console.log(`Demande de récuperaction du groupe venant de ${prof}`);
  db.all('SELECT * FROM groupe WHERE professeur like ?',[prof], (err, rows) => {
    if (err) {
      console.error(err);
      console.log(`\t-> Une erreur s'est produite : ${err.message}`);
      return res.status(500).json({ error: err.message });
    }  
    if(rows){
      const groupesDuProf = rows.map(row => row.id);
      console.log(`\t-> Le groupe à bien été trouvé : ${groupesDuProf}`);
      return res.status(200).json({ message: 'success', groupes: groupesDuProf });
    } else {
      console.log(`\t-> Aucun groupe trouvé`);
      return res.status(404).json({ error: 'Not Found'});
    }
  });
});


app.get('/getElevesDuGroupe', (req, res) => {
  const { groupe } = req.query;
  db.all('SELECT * FROM eleve WHERE groupeId like ?', [groupe], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }
    if (rows) {
      const elevesDuGroupe = rows.map(row => row.login); 
      return res.status(200).json({ message: 'success', eleves: elevesDuGroupe });
    } else {
      return res.status(404).json({ error: 'Not Found'});
    }
  });
});

// Endpoint pour récupérer les détails d'un élève spécifique
app.get('/getEleveDetails', (req, res) => {
  const { login } = req.query;


  // Recherche dans la base de données pour trouver l'élève en fonction du login
  db.get('SELECT * FROM eleve WHERE login = ?', [login], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }

    if (row) {
      // Si l'élève correspondant est trouvé, renvoyer les détails de l'élève
      return res.status(200).json({
        message: 'success',
        login: row.login,
        nom: row.nom,
        prenom: row.prenom,
        dateNaiss: row.dateNaiss,
        group: row.groupeId,
        qcm: row.qcm,
        tuto : row.tuto
        // Ajoutez d'autres propriétés selon votre modèle de données
        
      });
    } else {
      // Si l'élève n'est pas trouvé, renvoyer un message d'erreur
      return res.status(404).json({ error: 'Not Found'});
    }
  });
});

app.get('/getElevesSansGroupe', (req, res) => {
  db.all('SELECT * FROM eleve where groupeid is null', (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }
    if (rows) {
      const eleves = rows.map(row => row.login); 
      return res.status(200).json({ message: 'success', eleves: eleves });
    } else {
      return res.status(404).json({ error: 'Not Found'});
    }
  });
});

// endpoint récupérer le qcm de leleve
app.get('/hasDoneQcm', (req, res) => {
  const { login } = req.query;


  // Recherche dans la base de données pour trouver l'élève en fonction du login
  db.get('SELECT * FROM eleve WHERE login = ?', [login], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }

    if (row) {
      // Si l'élève correspondant est trouvé, renvoyer les détails de l'élève
      return res.status(200).json({
        message: 'success',
        qcm: row.qcm,
        
        
      });
    } else {
      // Si l'élève n'est pas trouvé, renvoyer un message d'erreur
      return res.status(404).json({ error: 'Not Found' });
    }
  });
});


// endpoint récupérer le qcm de leleve
app.get('/hasDoneTuto', (req, res) => {
  const { login } = req.query;


  // Recherche dans la base de données pour trouver l'élève en fonction du login
  db.get('SELECT * FROM eleve WHERE login = ?', [login], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }

    if (row) {
      // Si l'élève correspondant est trouvé, renvoyer les détails de l'élève
      return res.status(200).json({
        message: 'success',
        tuto: row.tuto,
        
        
      });
    } else {
      // Si l'élève n'est pas trouvé, renvoyer un message d'erreur
      return res.status(404).json({ message: 'Not Found' });
    }
  });
});

// endpoint récupérer la difficulte du groupe
app.get('/getDifficulteGame', (req, res) => {
  const { group } = req.query;


  // Recherche dans la base de données pour trouver l'élève en fonction du login
  db.get('SELECT * FROM groupe WHERE id = ?', [group], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }

    if (row) {
      // Si l'élève correspondant est trouvé, renvoyer les détails de l'élève
      return res.status(200).json({
        message: 'success',
        difficulte: row.difficulte,
        
        
      });
    } else {
      // Si l'élève n'est pas trouvé, renvoyer un message d'erreur
      return res.status(404).json({ message: 'Not Found' });
    }
  });
});


// endpoint mettre a jour le qcm
app.post('/majQcm', (req, res) => {
  const { login, qcmNew } = req.query; // Récupérer les données depuis le corps de la requête
  console.log(`Demande de mise a jour de qcm reçue : pour ${login} et jeu ${qcmNew}`);
  
  db.run(`UPDATE eleve SET qcm = ? WHERE login = ?`, [qcmNew, login], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    } else {
      // Ajoutez ce console.log pour afficher la ligne mise à jour
      db.get('SELECT * FROM eleve WHERE login = ?', [login], (err, row) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: err.message });
        }
        
        if (row) {
          console.log('\t-> Row après mise à jour :', row);
          return res.status(200).json({ message: 'success' });
        } else {
          return res.status(404).json({ error: 'Not Found' });
        }
      });
    }
  });
});

// endpoint mettre a jour le qcm
app.post('/majTuto', (req, res) => {
  const { login, tutoNew } = req.query; // Récupérer les données depuis le corps de la requête
  console.log(`demande de mise a jour de tuto reçue : pour ${login} et jeu ${tutoNew}`);
  
  db.run(`UPDATE eleve SET tuto = ? WHERE login = ?`, [tutoNew, login], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    } else {
      // Ajoutez ce console.log pour afficher la ligne mise à jour
      db.get('SELECT * FROM eleve WHERE login = ?', [login], (err, row) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: err.message });
        }

        if (row) {
          console.log('\t-> Row après mise à jour :', row);
          return res.status(200).json({ message: 'success' });
        } else {
          return res.status(404).json({ error: 'Not Found' });
        }
      });
    }
  });
});

// endpoint mettre a jour le qcm
app.post('/majDifficulte', (req, res) => {
  const { group, qcmNew } = req.query; // Récupérer les données depuis le corps de la requête
  console.log(`demande de mise a jour de difficulte reçue : pour ${group} et jeu ${qcmNew}`);
  
  db.run(`UPDATE groupe SET difficulte = ? WHERE id = ?`, [qcmNew, group], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    } else {
      // Ajoutez ce console.log pour afficher la ligne mise à jour
      db.get('SELECT * FROM groupe WHERE id = ?', [group], (err, row) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: err.message });
        }

        if (row) {
          console.log('\t-> Row après mise à jour :', row);
          return res.status(200).json({ message: 'success' });
        } else {
          return res.status(404).json({ error: 'Not Found' });
        }
      });
    }
  });
});

app.post('/updateEleveLogin', (req, res) => {
  const { currentLogin, newLogin } = req.body;

  // Vérifier si le nouvel identifiant existe déjà
  db.get('SELECT login FROM eleve WHERE login = ?', [newLogin], (err, existingRow) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    }

    if (existingRow) {
      // Si le nouvel identifiant existe déjà, renvoyer une erreur
      return res.status(400).json({ error: 'Bad Request' });
    } else {
      // Mettre à jour l'identifiant de l'élève
      db.run('UPDATE eleve SET login = ? WHERE login = ?', [newLogin, currentLogin], function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: err.message });
        }

        // Vérifier si la mise à jour a affecté une ligne
        if (this.changes > 0) {
          // Envoyer une réponse de succès
          res.status(200).json({ message: 'success' });
          console.log(`Mise à jour de l'identifiant de ${currentLogin} à ${newLogin}`);
        } else {
          // Si aucune ligne n'a été affectée, l'élève avec l'identifiant actuel n'a pas été trouvé
          res.status(404).json({ error: 'Not Found' });
        }
      });
    }
  });
});



// Endpoint pour la recherche de parties
// Endpoint pour la recherche de parties
app.post('/recherchePartie', (req, res) => {
  const { login, groupeId } = req.body;
  let rechercheCount = 0;

  // Fonction pour effectuer la recherche
  const performRecherche = () => {
    // Insérer une ligne dans la table squisine avec les paramètres fournis
    db.run(`INSERT INTO squisine (login, etat, tour, groupeId) VALUES (?, 'recherche', 'oui', ?)`, [login, groupeId], function (err) {
      if (err) {
        console.log('1');
        console.error(err);
        return res.status(500).json({ error: err.message });
      }

      console.log(`Recherche de partie enregistrée pour ${login} dans le groupe ${groupeId}`);
      
      // Fonction pour vérifier périodiquement s'il y a une partie disponible
      const checkPartieDisponible = () => {
        rechercheCount++;

        // Arrêter la recherche après 10 tentatives
        if (rechercheCount > 10) {
          
              console.log(`pas de partie trouvée pour ${login}`);
              db.run(`DELETE FROM squisine WHERE login = ? AND groupeId = ?`, [login, groupeId], function (deleteErr) {
                if (deleteErr) {
                  console.error(deleteErr);
                }
                else{
                  console.log(`Suppression des parties pour l'utilisateur ${login}.`);
                }
              });
              return res.status(200).json({ message: 'Nombre maximum de tentatives atteint' });
           
        }

        // Rechercher une ligne dans la table squisine où etat='recherche', groupeId correspond à celui fourni, et login différent du login en paramètre
        db.get('SELECT * FROM squisine WHERE etat = "recherche" AND groupeId = ? AND login != ?', [groupeId, login], (err, row) => {
          if (err) {
            console.log('2');
            console.error(err);
            return res.status(500).json({ error: err.message });
          }
          console.log('recherche en cours...');
          if (row) {
            // Si une partie est disponible, mettre à jour les lignes pour passer à l'état 'jeu'
            db.run(`UPDATE squisine SET etat = "jeu", coequipier = ? WHERE (etat = 'recherche') AND groupeId = ? AND login=?`, [login, groupeId, row.login], function (err) {
              if (err) {
                console.log('3');
                console.error(err);
                // Supprimer la ligne insérée en cas d'erreur après l'insertion
                db.run(`DELETE FROM squisine WHERE login = ? AND groupeId = ?`, [login, groupeId], function (deleteErr) {
                  if (deleteErr) {
                    console.error(deleteErr);
                  }
                });
                return res.status(500).json({ error: err.message });
              }
            });
            db.run(`UPDATE squisine SET etat = "jeu", coequipier = ? WHERE (etat = 'recherche') AND groupeId = ? AND login=?`, [row.login, groupeId, login], function (err) {
              if (err) {
                console.log('3');
                console.error(err);
                // Supprimer la ligne insérée en cas d'erreur après l'insertion
                db.run(`DELETE FROM squisine WHERE login = ? AND groupeId = ?`, [login, groupeId], function (deleteErr) {
                  if (deleteErr) {
                    console.error(deleteErr);
                  }
                });
                return res.status(500).json({ error: err.message });
              }

              console.log(`Partie trouvée pour ${login} dans le groupe ${groupeId}`);
              db.run(`UPDATE squisine SET tour = "non" WHERE etat="jeu" AND groupeId = ? AND login = ?`, [groupeId,row.login], function (err) {
                if (err) {
                  console.error(err);
                  return res.status(500).json({ error: err.message });
                }
                console.log('maj tour');
              });

              db.all('SELECT * FROM squisine', (err, row) => {
                if (err) {
                  console.error(err);
                  return res.status(500).json({ error: err.message });
                }
                
                if (row) {
                  console.log('\t-> Row après mise à jour :', row);
                  return res.status(200).json({ message: 'success' });
                } else {
                  return res.status(404).json({ error: 'Not Found' });
                }
              });
              
            });
          } else {
            db.get('SELECT * FROM squisine WHERE etat = "jeu" AND groupeId = ? AND login = ?', [groupeId, login], (err, row) => {
              console.log('passe ici 1');
              if (err) {
                console.log('0');
                console.error(err);
                return res.status(500).json({ error: err.message });
              }
              if (row) {
                console.log('passe ici 2');
                console.log('partie trouvee quand recherche finie');
                return res.status(200).json({ message: 'success' });
              }
              else{
                console.log('passe ici 3');
                // Si aucune partie n'est trouvée, répéter la vérification après un délai
                setTimeout(checkPartieDisponible, 1000); // ajustez le délai selon vos besoins
              }
            });
          }
        });
      };

     

      // Lancer la vérification initiale
      checkPartieDisponible();
    });
  };

  // Démarrer la recherche
  performRecherche();
});


//endpoint pour récupérer le cooequipier courant
app.get('/getCoequipier', (req, res) => {
  const { login } = req.query;


  // Recherche dans la base de données pour trouver l'élève en fonction du login
  db.get('SELECT * FROM squisine WHERE login = ?', [login], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }

    if (row) {
      return res.status(200).json({
        message: 'success',
        coequipier: row.coequipier,
        tour: row.tour
      });
    } else {
      // Si l'élève n'est pas trouvé, renvoyer un message d'erreur
      return res.status(500).json({ error: 'pas trouvé eleve'});
    }
  });
});


//endpoint pour récupérer le tour courant
app.get('/getTour', (req, res) => {
  const { coop } = req.query;


  // Recherche dans la base de données pour trouver l'élève en fonction du login
  db.get('SELECT tour FROM squisine WHERE login = ?', [coop], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: err.message });
    }
    if (row) {
      return res.status(200).json({
        message: 'success',
        tour: row.tour
      });
    } else {
      // Si l'élève n'est pas trouvé, renvoyer un message d'erreur
      return res.status(404).json({ error: 'Not Found'});
    }
  });
});


// endpoint mettre a jour le tour
app.post('/majTour', (req, res) => {
  const { login,coeq } = req.body; // Récupérer les données depuis le corps de la requête
  console.log(`demande de mise a jour de tour reçue : pour ${login}`);
  
  
  db.run(`UPDATE squisine SET tour="oui" WHERE login = ?`, [coeq], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    }
  });
  db.run(`UPDATE squisine SET tour="non" WHERE login = ?`, [login], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    } else {
      // Ajoutez ce console.log pour afficher la ligne mise à jour
      db.get('SELECT * FROM squisine', (err, row) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: err.message });
        }
        if (row) {
          
          db.all('SELECT * FROM squisine', (err, row) => {
            if (err) {
              console.error(err);
              return res.status(500).json({ error: err.message });
            }
            
            if (row) {
              console.log('\t-> Row après mise à jour :', row);
              return res.status(200).json({ message: 'success' });
            } else {
              return res.status(404).json({ error: 'Not Found' });
            }
          });
        } else {
          return res.status(404).json({ error: 'Not Found' });
        }
      });
    }
  });
});


app.post('/finJeu', (req, res) => {
  const { login,typefin } = req.body;
  // Supprimer les lignes dans la table squisine où login correspond à celui fourni
  db.run(`UPDATE squisine SET tour=? WHERE login = ?`, [typefin, login], function (err) {    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    }

    db.all('SELECT * FROM squisine', (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
      }
      
      if (row) {
        console.log('\t-> Row après mise à jour :', row);
        return res.status(200).json({ message: 'success' });
      } else {
        return res.status(404).json({ error: 'Not Found' });
      }
    });

  });
});

// Supression des données d'un utilisateur au bout de 6 mois d'inactivité
function supprimerUtilisateursInactifs(table) {
  const sixMoisAvant = new Date();
  sixMoisAvant.setMonth(sixMoisAvant.getMonth() - 6);

  const query = `DELETE FROM ${table} WHERE lastConnexion < ?`;

  db.run(query, sixMoisAvant.toISOString(), (err) => {
    if (err) {
      console.error(`Erreur lors de la suppression des ${table} inactifs :`, err.message);
    } else {
      console.log(`${table} inactifs supprimés avec succès.`);
    }
  });
}

// Planifier l'exécution quotidienne à minuit pour les élèves
cron.schedule('0 0 * * *', () => {
  console.log('Exécution quotidienne de la vérification des élèves inactifs...');
  supprimerUtilisateursInactifs('ELEVE');
});

// Planifier l'exécution quotidienne à minuit pour les professeurs
cron.schedule('0 0 * * *', () => {
  console.log('Exécution quotidienne de la vérification des professeurs inactifs...');
  supprimerUtilisateursInactifs('PROFESSEUR');
});

// Endpoint pour supprimer les parties
app.post('/clearGames', (req, res) => {
  const { login } = req.body;

  // Supprimer les lignes dans la table squisine où login correspond à celui fourni
  db.run(`DELETE FROM squisine WHERE login = ?`, [login], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    }

    // Vérifier le nombre de lignes supprimées
    const rowsAffected = this.changes;
    if (rowsAffected > 0) {
      console.log(`Suppression des parties pour l'utilisateur ${login}. ${rowsAffected} lignes supprimées.`);
      return res.status(200).json({ message: 'success', rowsAffected });
    } else {
      console.log(`Aucune partie trouvée pour l'utilisateur ${login}. Aucune ligne supprimée.`);
      return res.status(404).json({ error: 'Not Found' });
    }
  });
});

// Suppresion d'un utilisateur sur demande
app.post('/deleteUser', (req, res) => {
  const { login, teacher } = req.body;
  
  if (!teacher) {
    db.run('DELETE FROM eleve WHERE login = ?', [login], (err, existingRow) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
      }

      console.log(`Utilisateur eleve supprimé avec succès: ${login}`);
      return res.status(200).json({ message: 'Utilisateur supprimé avec succès.' });
    });
  } else { 
    db.run('DELETE FROM professeur WHERE login = ?', [login], (err, existingRow) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
      }

      console.log(`Utilisateur professeur supprimé avec succès: ${login}`);
      return res.status(200).json({ message: 'Utilisateur supprimé avec succès.' });
    });
  }
});

app.post('/addSentenceInformatico', (req, res) => {
  const { login, sentence } = req.body;
  console.log(`Demande d'ajout de phrase lue par informatico : phrase ${sentence}, par ${login}`)

    db.get('SELECT * FROM informatico WHERE login = ?', [login], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: err.message });
      }

      if (!row) {
        db.run('INSERT INTO informatico (login, sentences) VALUES (?, ?)', [login, sentence], (err) => {
          if (err) {
            console.error(err);
          }
          console.log(`\t-> L'utilisateur n'a jamais lu de phrases : ajout d'une ligne dans la table`);
        } );
      } else {
        db.get('SELECT sentences FROM informatico WHERE login = ?', [login], (err, row) => {
          if (err) {
            console.error(err);
          } else {
            console.log(`\t-> L'utilisateur a déjà lu des phrases : ${row.sentences}`);
            db.run('UPDATE informatico SET sentences = ? WHERE login = ?', [row.sentences+','+sentence, login], (err) => {
          });
        }
        });
      }
    });
  
});

app.get('/getSentencesInformatico', (req, res) => {
  const { login } = req.query;
  console.log(`demande de récuperation de phrases informatico par ${login}`)
  db.get('SELECT sentences FROM informatico WHERE login = ?', [login], (err, row) => {
    if (err) {
      console.error(err);
    } else {
      if (row) {
        console.log(`\t-> Les phrases suivantes on été trouvées, et retournées : ${row.sentences}`);
        return res.status(200).json({ sentences: row.sentences });
      } else {
        console.log(`Aucune phrase trouvé pour cet utilisateur`);
        return res.status(404).json({ message: 'No user with username \''+login+'\' has been found.' });
      }
    }
  });
});

const port = 5000;

app.listen(5000, () => {
  console.log('Server running on port 5000');
});





