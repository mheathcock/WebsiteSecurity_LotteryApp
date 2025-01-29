# IMPORTS
import logging
import numbers

from flask_login import current_user

from flask import Blueprint, render_template, request, flash
from sqlalchemy.orm import make_transient

from app import db
from models import Draw


from users.views import requires_roles

# CONFIG
lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@requires_roles('user')
def lottery():
    return render_template('lottery/lottery.html')


@lottery_blueprint.route('/add_draw', methods=['POST'])
@requires_roles('user')
def add_draw():
    submitted_draw = ''
    for i in range(6):
        submitted_draw += request.form.get('no' + str(i + 1)) + ' '
    submitted_draw.strip()

    # create a new draw with the form data. and encryts the users numbers
    new_draw = Draw(user_id=current_user.id,
                    numbers=submitted_draw,
                    master_draw=False, lottery_round=0, secret_key=current_user.secret_key)

    # add the new draw to the database

    db.session.add(new_draw)

    db.session.commit()

    # re-render lottery.page
    flash('Draw %s submitted.' % submitted_draw)
    return lottery()


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@requires_roles('user')
def view_draws():
    # get all draws that have not been played [played=0]

    playable_draws = Draw.query.filter_by(been_played=False, user_id=current_user.id).all()
    print(playable_draws)
    # if playable draws exist
    if len(playable_draws) != 0:
        # re-render lottery page with playable draws
        for draw in playable_draws:
            make_transient(draw)
            draw.view_numbers(current_user.secret_key)
        return render_template('lottery/lottery.html', playable_draws=playable_draws)
    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@requires_roles('user')
def check_draws():
    # played draws query the database for draws that have been played by the current user
    played_draws = Draw.query.filter_by(been_played=True, user_id=current_user.id).all()

    # if played draws exist
    if len(played_draws) != 0:
        for draw in played_draws:  # for every draw
            make_transient(draw)  # Before the draw can be decrypted it needs to be disconnected (made independent) of
            # the database by making it transient.
            draw.view_numbers(current_user.secret_key)  # use the view_numbers function in models.py to decrypt the
            # numbers in the draw using the users secret key

        return render_template('lottery/lottery.html', results=played_draws, played=True)

    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# delete all played draws
@lottery_blueprint.route('/play_again', methods=['POST'])
@requires_roles('user')
def play_again():
    Draw.query.filter_by(been_played=True, master_draw=False).delete(synchronize_session=False)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()
