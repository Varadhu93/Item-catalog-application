from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catalog, Item, User
engine = create_engine('sqlite:///itemcatalog.db')


Base.metadata.bind = engine
DBsession = sessionmaker(bind=engine)
session = DBsession()


catalog1 = Catalog(name='Soccer')
session.add(catalog1)
session.commit()


catalog1 = session.query(Catalog).filter_by(name='Soccer').one()

item1 = Item(title="Referee", description="""referee is the person responsible
             for enforcing the Laws of the Game during the course of a match.
             He or she is the final decision-making authority on all facts
             connected with play, and is the only official on the pitch with
             the authority to start and stop play and impose disciplinary
             action against players during a match.""",
             catalog_id=catalog1.id)
session.add(item1)
session.commit()


item2 = Item(title="Soccer Ball", description="""A ball is a round object(
             usually spherical but sometimes ovoid) with various uses. It is
             used in ball games, where the play of the game follows the state
             of the ball as it is hit, kicked or thrown by players. Balls can
             also be used for simpler activities, such as catch, marbles and
             juggling.""", catalog_id=catalog1.id)
session.add(item2)
session.commit()


item3 = Item(title="Football pitch", description="""A football pitch alsoknown
             as a football field or soccer field is the playing surface for
             the game of association football. Its dimensions and markings are
             defined by law 1 of the laws of the game, the field of play can
             be either natural or artificial.""", catalog_id=catalog1.id)
session.add(item3)
session.commit()


catalog2 = Catalog(name='Basketball')
session.add(catalog2)
session.commit()
catalog2 = session.query(Catalog).filter_by(name='Basketball').one()


item1 = Item(title="Hoop", description="""A circular strip used especially for
             holding together the staves of containers or as a plaything""",
             catalog_id=catalog2.id)
session.add(item1)
session.commit()


catalog3 = Catalog(name='Snowboard')
session.add(catalog3)
session.commit()
catalog3 = session.query(Catalog).filter_by(name='Snowboard').one()


item1 = Item(title="Snowboard", description="""Snowboards are boards where both
             feet are secured to the same board, which are wider than skis,
             with the ability to glide on snow.""", catalog_id=catalog3.id)
session.add(item1)
session.commit()


catalog4 = Catalog(name='Tennis')
session.add(catalog4)
session.commit()
catalog4 = session.query(Catalog).filter_by(name='Tennis').one()


item1 = Item(title="Tennis", description="""Tennis is a racket sport that
             can be played individually against a single opponent(singles) or
             between two teams of two players
             each(doubles). Each player uses a tennis racket that is strung
             with cord to strike a hollow rubber ball covered with felt
             over or around a net and into the opponent's court.""",
             catalog_id=catalog4.id)
session.add(item1)
session.commit()


item2 = Item(title="Racket", description="""A racket or racquet is a sports
             implement consisting of a handled frame with an open hoop across
             which a network of strings or catgut is stretched tightly. It is
             used for striking a ball or shuttlecock in games such as squash,
             tennis, racquetball, and badminton.""", catalog_id=catalog4.id)
session.add(item2)
session.commit()


item3 = Item(title="Racquetball", description="""Racquetball is a racquet sport
             played with a hollow rubber ball in an indoor or outdoor court.
             Joseph Sobek is credited with inventing the modern sport of
             racquetball in 1950.""", catalog_id=catalog4.id)
session.add(item3)
session.commit()


item4 = Item(title="Tennis court", description="""A tennis court is the
             venue where the sport of tennis is played. It is a firm
             rectangular surface with a low net stretched across the center.
             The same surface can be used to play both doubles and singles
             matches. A variety of surfaces can be used to create a tennis
             court, each with its own characteristics which affect the playing
             style of the game.""", catalog_id=catalog4.id)
session.add(item4)
session.commit()


catalog5 = Catalog(name='Hockey')
session.add(catalog5)
session.commit()
catalog5 = session.query(Catalog).filter_by(name='Hockey').one()


item1 = Item(title="Hockey", description="""Hockey is a sport in which two
             teams play against each other by trying to maneuver a ball or a
             puck into the opponent's goal using a hockey stick. There are
             many types of hockey such as bandy,
             field hockey and ice hockey.""",
             catalog_id=catalog5.id)
session.add(item1)
session.commit()


item2 = Item(title="Hockey stick", description="""A hockey stick is a piece
             of equipment used by the players in most forms of hockey to move
             the ball or puck.""", catalog_id=catalog5.id)
session.add(item2)
session.commit()


item3 = Item(title="Hockey puck", description="""A hockey puck is a disk
             made of vulcanized rubber that serves the same functions in
             various games as a ball does in ball games. The best-known use of
             pucks is in ice hockey, a major international sport.""",
             catalog_id=catalog5.id)
session.add(item3)
session.commit()
