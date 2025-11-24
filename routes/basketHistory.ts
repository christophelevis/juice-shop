/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

import models = require('../models/index')
const utils = require('../lib/utils')
const security = require('../lib/insecurity')

// vuln-code-snippet start basketHistorySqlInjection
module.exports = function basketHistory () {
  return (req, res, next) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))

    if (!loggedInUser?.data?.id) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const userId = loggedInUser.data.id
    let sortBy = req.query.sortBy || 'id'
    const sortOrder = req.query.order || 'ASC'

    // Vulnerable SQL query with ORDER BY injection
    // This allows attackers to inject SQL in the ORDER BY clause
    const query = `SELECT * FROM Baskets WHERE UserId = ${userId} ORDER BY ${sortBy} ${sortOrder}` // vuln-code-snippet vuln-line basketHistorySqlInjection

    models.sequelize.query(query)
      .then(([baskets]) => {
        // Fetch basket items for each basket
        const basketPromises = baskets.map((basket: any) => {
          return models.BasketItem.findAll({
            where: { BasketId: basket.id },
            include: [{ model: models.Product }]
          })
        })

        return Promise.all(basketPromises).then(items => {
          baskets.forEach((basket: any, index: number) => {
            basket.Products = items[index]
          })
          return baskets
        })
      })
      .then((baskets) => {
        res.status(200).json({ status: 'success', data: baskets })
      })
      .catch(error => {
        next(error)
      })
  }
}
// vuln-code-snippet end basketHistorySqlInjection
